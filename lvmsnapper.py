#!/usr/bin/env python3
#
# Copyright (C) 2015 Koen Zandberg <hydrazine@bergzand.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from datetime import datetime, timedelta
import re
import configparser
import shlex
from collections import OrderedDict, namedtuple
import subprocess
import os
import logging
from logging import handlers
import pickle
import fcntl

# do nothing if True, useful for testing
NOOP = False

# default config location
CONFIGFILE = '/etc/lvmsnapper.conf'

#
SYSSECTIONS = ['main', 'logging', 'expire_']

# The tag to use for volumes
LVM2_TAG = 'snapper'

# Info about the ranges of time definitions
TIME = {
    'hours': list(range(0, 24)),
    'dow': list(range(1, 8)),
    'dom': list(range(1, 32)),
    'months': list(range(1, 13))
}

# LVM binary path
LVM = "/sbin/lvm"

# Data we need for snapshots
SnapShot = namedtuple('SnapShot', ['mountpoint',
                                   'mountopts',
                                   'snapmount',
                                   'snaplv',
                                   'origlv',
                                   'vg',
                                   'linkname',
                                   'nfsexports',
                                   'nfsopts',
                                   'creationtime',
                                   'expiration'])

# The regex to parse expiration strings
expire_syn = re.compile(
    r'''
        (?:(?P<hours>\d{1,2})\s?(?:[Hh]ours?)\s*,?\s*)? #parse hours if available
        (?:(?P<days>\d{1,3})\s?(?:[Dd](?:ays?)?)\s*,?\s*)? #Get day if available
        (?:(?P<weeks>\d{1,3})\s?(?:[Ww](?:eeks?)?))? #week parser
    ''',
    re.VERBOSE
    )

# Regex to parse the key value pairs from the "lvs" output
lvm_parser = re.compile(
    r'''
        (?P<key>\w+)=      # Key consists of only alphanumerics
        (?P<quote>["']?)   # Optional quote character.
        (?P<value>.*?)     # Value is a non greedy match
        (?P=quote)         # Closing quote equals the first.
        ($|,)              # Entry ends with comma or end of string
    ''',
    re.VERBOSE
    )

# Different loglevels to configure
loglevels = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

# Total error count when parsing the config
errors = 0


def inc_errors():
    """
    Increment the global error count by one
    :return: None
    """
    global errors
    errors += 1


def check_lvm(volume_name, volume_group):
    """
    Check if the lvm volume exists by calling lvs with the volume group and volume name
    :param volume_name: The name of the logical volume to check
    :param volume_group: The name of the volume group that has the logical volume
    :return: True if the volume exists
    """
    name = '/'.join([volume_group, volume_name])
    try:
        subprocess.check_call([LVM, "lvs", name],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def check_snapdir(directory):
    """
    Check if the configured snapshot directory is a valid path
    :param directory:
    :return: True if the path is a valid path
    """
    return os.path.isdir(directory) and os.path.isabs(directory)


def check_mount(directory):
    """
    Check if the configured mount point is valid
    :param directory:
    :return: True if it is a valid mount point
    """
    return os.path.ismount(directory) and os.path.isabs(directory)


def get_snapdirs(config_options):
    """
    Parse the configuration file for sections that define a snapshot
    Each section is checked, Sections that are not one of the main sections
    are considered snapshots. The options are checked for needed and valid
    options
    :param config_options: The dictionary that contains the config options
    :return: A list of dictionaries that contain snapshot configurations
    """
    for confsec in config_options.sections()[:]:
        for syssec in SYSSECTIONS:
            if confsec.startswith(syssec):
                config_options.remove_section(confsec)
    logger.info("Found {} snapshot configurations.".format(len(config_options.sections())))
    snapdirs = []
    for snapsec in config_options.sections():
        # Check the mountpath option, OK if dir exists, else throw an error to user
        try:
            mountpath = config_options.get(snapsec, 'mount')
        except configparser.NoOptionError:
            logger.error("No mount option found in {}.".format(snapsec))
            inc_errors()
            continue
        if not check_mount(mountpath):
            logger.error("Mount path \"{}\" not an absolute mount point ".format(mountpath))
            inc_errors()
            continue
        # Check the mountoptions option, OK if the option exists, else set it to None
        try:
            mountoptions = config_options.get(snapsec, 'mountoptions')
        except configparser.NoOptionError:
            mountoptions = None

        # Check the logical volume option, OK if exists, else throw an error to user
        try:
            lvoption = config_options.get(snapsec, 'lv')
        except configparser.NoOptionError:
            logger.error("No logical volume option (lv) found in {}.".format(snapsec))
            inc_errors()
            continue

        # And check the volume group option
        try:
            vgoption = config_options.get(snapsec, 'vg')
        except configparser.NoOptionError:
            logger.error("No volume group option (vg) found in {}.".format(snapsec))
            inc_errors()
            continue
        # Check whether a valid logical volume was supplied
        if not check_lvm(lvoption, vgoption):
            logger.error("No logical volume found with path {0}/{1}.".format(vgoption, lvoption))
            inc_errors()
        # Check if a snapshotdir was supplied.
        try:
            snapdiroption = config_options.get(snapsec, 'snapdir')
        except configparser.NoOptionError:
            logger.error("No snapdir option found in {}.".format(snapsec))
            inc_errors()
            continue
        if not check_snapdir(snapdiroption):
            logger.error("Snapdir not an absolute directory: \"{}\".".format(snapdiroption))
            inc_errors()
            continue
        try:
            linkdiroption = config_options.get(snapsec, 'linkdir')
            if not os.path.exists(linkdiroption):
                logger.error("linkdir path \"{}\" does not exits".format(linkdiroption))
                inc_errors()
        except configparser.NoOptionError:
            linkdiroption = None

        # check for nfs options
        try:
            nfsexports = config_options.get(snapsec, 'nfsexports')
        except configparser.NoOptionError:
            nfsexports = None
        try:
            nfsoptions = config_options.get(snapsec, 'nfsoptions')
        except configparser.NoOptionError:
            nfsoptions = None
        logger.info("Parsed snapshot dir {}".format(snapsec))
        snapdirs.append({'mount': mountpath,
                         'vg': vgoption,
                         'lv': lvoption,
                         'snapdir': snapdiroption,
                         'mountoptions': mountoptions,
                         'linkdir': linkdiroption,
                         'nfsexports': nfsexports,
                         'nfsoptions': nfsoptions
                         })
    return snapdirs


def parse_nfs(nfsexports):
    """
    Validate and parse the configuration of the nfs exports
    :param nfsexports: A string of export hosts/networks
    :return: a list with the exports
    """
    lexer = shlex.shlex(nfsexports)
    lexer.wordchars += '/.'
    exports = [export for export in lexer]
    logger.info("Found the following exports: " + ' '.join(exports))
    return exports


def parse_expires(expire):
    """
    Uses the regex to parse an expire into a dict
    :param expire: A config string with expires
    :return: None if failed to parse, A dictionary otherwise
    """
    match = expire_syn.fullmatch(expire)
    if match:
        expire_info = {key: int(value) for key, value in match.groupdict(default=0).items()}
        logger.debug("Correctly parsed \"{}\" to a time".format(expire))
        return timedelta(**expire_info)
    else:
        return None


def parse_time(match):
    """
    Parse the cron like syntax to a dict.
    each value is an array with the moments it should match
    :param match: A string to convert
    :return: None if failed, a dict with the matching time moments if
                  it was possible to parse
    """
    lexer = shlex.shlex(match)
    lexer.wordchars += '/*,'
    args = [arg for arg in lexer]
    if len(args) is not 4:
        return None
    else:
        preconv = dict(zip(['hours', 'dow', 'dom', 'months'], args))
        postconv = {}
        for key, value in preconv.items():
            parsedvalue = []
            timelexer = shlex.shlex(value)
            timelexer.whitespace = ','
            timelexer.wordchars = '0123456789/*'
            timelexer.whitespace_split = True
            for token in timelexer:
                # case *
                if token == '*':
                    parsedvalue.extend(TIME[key])
                # case */divisor
                elif re.fullmatch('\*/\d+', token):
                    divisor = int(token.split('/')[1])
                    for num in TIME[key]:
                        if num/divisor == int(num/divisor):
                            parsedvalue.append(num)
                else:
                    try:
                        parsedvalue.append(int(token))
                    except TypeError:
                        logger.error("Incorrect match found in config: {0}".format(match))
                        inc_errors()
                        break
            else:
                postconv[key] = list(OrderedDict.fromkeys(parsedvalue))
                continue
            break
        else:
            logger.debug("Correctly parsed {0} to values".format(match))
            return postconv
        return None


def get_expires(config_options):
    """
    Parse all config sections that begin with "expire_". These contain
    expire rules for snapshots.

    :param config_options: The configuration dictionary
    :return: A list with expire data
    """
    expire_sections = {}
    for section in config_options.sections():
        if section.startswith('expire_'):
            logger.debug("Trying to parse section {0}.".format(section))
            # First we test whether the time is correctly formatted.
            try:
                time = parse_time(config_options[section]['match'])
            except KeyError:
                # No match block found.
                logger.error("Config section {} has no match option".format(section))
                inc_errors()
                continue
            # match was not correct.
            if not time:
                continue
            # Now we test the expire rule.
            expire_rule = config_options[section]['expire_after']
            try:
                expire_time = parse_expires(expire_rule)
            except KeyError:
                logger.error("Config section {} has no expire option".format(section))
                inc_errors()
                continue
            if not expire_time:
                logger.error("Could not parse expire rule from section {0} to a time: \"{1}\"".format(section,
                                                                                                      expire_rule))
            # And if everything is correct we add it.
            expire_sections[section] = {
                'match': time,
                'expire': expire_time
            }
    logger.info("Found {0} correct expire sections".format(len(expire_sections)))
    expirelist = OrderedDict.fromkeys('')
    # Sort might not be needed.
    for key, values in sorted(expire_sections.items()):
        expirelist[key] = values
    return expirelist


def check_time(current_time, match_time):
    """
    Check if an expire section matches with the current time
    :param current_time: A datetime object containing the current (UTC) time
    :param match_time: The time dict to check
    :return: True if it matches, false otherwise
    """
    if current_time.hour in match_time['hours'] \
            and current_time.day in match_time['dom'] \
            and current_time.month in match_time['months'] \
            and current_time.isoweekday() in match_time['dow']:
        return True
    else:
        return False


def get_longest_expire(expire_list, current_time):
    """
    Walks through the list of expiration, returning the longest expiration time that matches with the current time
    :param expire_list: The dictionary with timedelta objects and matching arrays from the parsed config
    :param current_time: datetime.now()
    :return: a timedelta object
    """
    longest = timedelta()
    for key, values in expire_list.items():
        if check_time(current_time, values['match']):
            delta = values['expire']
            if delta > longest:
                longest = delta
    if longest.total_seconds() == 0:
        return None
    else:
        return current_time + longest


def check_statefile(state_location):
    """
    Check whether the state file has a correct location.
    :param state_location: The path to the state file
    :return: a boolean
    """
    return os.path.abspath(state_location)


def make_snapshot(snapshot):
    """
    Call lvcreate to create the snapshot. If succesfully taken, add a
    tag to the snapshot to verify it when removing.
    :param snapshot: A snapshot namedTuple
    :return: True if succesfully snapshotted and tagged
    """
    orig_path = os.path.join(snapshot.vg, snapshot.origlv)
    command = [LVM, "lvcreate", "-s", "-n", snapshot.snaplv, orig_path]
    logger.debug("Executing command to make snapshot: {}".format(' '.join(command)))
    try:
        if not NOOP:
            subprocess.check_call([LVM, "lvcreate", "-s", "-n", snapshot.snaplv, orig_path])
    except subprocess.CalledProcessError as e:
        logger.error("Failed to make snapshot: {}".format(e))
        return False
    # tag the snapshot
    volume_name = os.path.join(snapshot.vg, snapshot.snaplv)
    tag_command = [LVM, "lvchange", "--addtag", LVM2_TAG, volume_name]
    try:
        subprocess.check_call(tag_command)
    except subprocess.CalledProcessError:
        logger.error("Unable to tag snapshot volume with: {}".format(' '.join(tag_command)))
        logger.error("Please manually remove this snapshot")
        return False
    return True


def snapshot_finish(snapshot):
    """
    Round up the snapshot creation:
    activate volume
    change uuid
    create snapshot directory for mounting
    Mount the snapshot at the location
    Create symlink is needed
    export over nfs if needed
    :param snapshot: SnapShot namedPickle
    :return: Whether successful
    """
    mount_device = os.path.join('/dev', snapshot.vg, snapshot.snaplv)
    activation_command = [LVM, "lvchange", "-ay", "-K", os.path.join(snapshot.vg, snapshot.snaplv)]
    subprocess.check_call(activation_command)
    uuid_command = ["/sbin/tune2fs", "-Utime", mount_device]
    subprocess.check_call(uuid_command)
    # create dir
    logger.debug("Creating directory: {}".format(snapshot.snapmount))
    if not NOOP:
        os.mkdir(snapshot.snapmount)
    # mounting
    if snapshot.mountopts:
        mount_opts = "-o" + snapshot.mountopts
    else:
        mount_opts = ''
    mount_command = ['mount', mount_opts, mount_device, snapshot.snapmount]
    logger.debug("Trying to mount with command: {}".format(' '.join(mount_command)))
    if not NOOP:
        try:
            subprocess.check_call(mount_command)
            mounted = True
        except subprocess.CalledProcessError:
            mounted = False
    else:
        # Fake correct mount
        mounted = True
    if mounted:
        # create symlink
        if snapshot.linkname:
            try:
                if not NOOP:
                    os.symlink(snapshot.snapmount, snapshot.linkname)
                logger.debug("Created symlink at {}.".format(snapshot.linkname))
            except os.error:
                logger.error("Failed to create symlink from {}.".format(snapshot.linkname))
        if snapshot.nfsexports:
            for export in snapshot.nfsexports:
                exports_combined = ':'.join([export, snapshot.snapmount])
                nfs_options = ''
                if snapshot.nfsopts:
                    nfs_options = '-o' + snapshot.nfsopts
                nfs_command = ['exportfs', exports_combined, nfs_options]
                logger.debug("Exporting nfs as: {}".format(' '.join(nfs_command)))
                if not NOOP:
                    subprocess.check_call(nfs_command)
    else:
        os.rmdir(snapshot.snapmount)


def create_all_snapshots(snapshots_conf, expiration_time, current_time, state):
    """
    For each snapshot configuration, create a snapshot and finish it up
    :param snapshots_conf:
    :param expiration_time:
    :param current_time:
    :param state:
    :return:
    """
    for snapshotconf in snapshots_conf:

        snapname = "{0}-{1}".format(snapshotconf['lv'],
                                    current_time.strftime("%Y%m%d%H%M%S"))
        logger.info("Creating snapshot with name: {0} from {1}".format(snapname,
                                                                       snapshotconf['lv']))
        if snapshotconf['nfsexports']:
            nfsclients = parse_nfs(snapshotconf['nfsexports'])
        else:
            nfsclients = None
        dirformat = current_time.strftime('@GMT-%Y.%m.%d-%H.%M.%S')
        dirname = os.path.join(snapshotconf['snapdir'], dirformat)
        linkname = os.path.join(snapshotconf['linkdir'], dirformat)

        snapshot = SnapShot(mountpoint=snapshotconf['mount'],
                            mountopts=snapshotconf['mountoptions'],
                            snapmount=dirname,
                            snaplv=snapname,
                            origlv=snapshotconf['lv'],
                            vg=snapshotconf['vg'],
                            linkname=linkname,
                            creationtime=current_time,
                            expiration=expiration_time,
                            nfsexports=nfsclients,
                            nfsopts=snapshotconf['nfsoptions']
                            )

        # make the actual snapshot
        result = make_snapshot(snapshot)
        if result:
            # finish up the snapshot (export, symlink etc)
            logger.debug("Finishing up snapshot {}".format(snapname))
            snapshot_finish(snapshot)
            state.append(snapshot)
        else:
            logger.error("Failed to create snapshot for {}".format(snapshot.mountpoint))
    return state


def snapshot_remove_before(snapshot):
    """
    Things to do before the snapshot can be removed:
    Unexport directory
    remove symlink
    unmount volume
    :param snapshot:
    :return: True if the volume can be removed
    """
    # exportfs doesn't seem to care if the directory unexported is an actual export
    for export in snapshot.nfsexports:
        exportcombined = ':'.join([export, snapshot.snapmount])
        unexportcommand = ["/usr/sbin/exportfs", "-u", exportcombined]
        logger.debug("Removing nfs export with: {}".format(' '.join(unexportcommand)))
        try:
            subprocess.check_call(unexportcommand)
        except subprocess.CalledProcessError:
            logger.error("Could not unexport the nfs export \"{}\", check manually".format(' '.join(unexportcommand)))
            return False
    # remove the symlink if created
    if snapshot.linkname and os.path.islink(snapshot.linkname):
        os.remove(snapshot.linkname)
    # unmount the volume
    if os.path.isdir(snapshot.snapmount):
        if os.path.ismount(snapshot.snapmount):
            unmountcommand = ["/bin/umount", snapshot.snapmount]
            try:
                subprocess.check_call(unmountcommand)
            except subprocess.CalledProcessError:
                logger.error("Unable to unmount \"{}\", please check manually for errors".format(snapshot.snapmount))
                return False
        else:
            logger.warn("Mount \"{}\" already unmounted".format(snapshot.snapmount))
        os.rmdir(snapshot.snapmount)
    else:
        logger.warn("Mount directory \"{}\" of snapshot already removed".format(snapshot.snapmount))
    return True


def snapshot_remove(snapshot):
    """
    Verify that we're removing a snapshot, then remove volume
    :param snapshot:
    :return: True if the snapshot was removed
    """
    volname = os.path.join(snapshot.vg, snapshot.snaplv)
    lvscommand = [LVM,
                  "lvs",
                  "-olv_name,lv_attr,lv_tags,origin",
                  "--noheadings",
                  "--nameprefixes",
                  "--separator=,",
                  volname]
    lv_info = ''
    try:
        lv_info = subprocess.check_output(lvscommand).decode('ascii')
    except subprocess.CalledProcessError:
        logger.error("Could not get ")
    d = {match.group('key'): match.group('value') for match in lvm_parser.finditer(lv_info)}
    assert d['LVM2_ORIGIN'] == snapshot.origlv
    assert d['LVM2_LV_ATTR'][0] == 'V'
    assert d['LVM2_LV_TAGS'] == LVM2_TAG
    remove_command = [LVM, "lvremove", "-f", volname]
    subprocess.check_call(remove_command)
    return True


def remove_expired(state, currenttime):
    """
    Check each snapshot in the state file for expiration and remove it
    :param state:
    :param currenttime:
    :return:
    """
    for snapshotconf in state[:]:
        if currenttime > snapshotconf.expiration:
            # Snapshot is outdated and must be removed
            logger.info("{} is scheduled for removal".format(snapshotconf.snaplv))
            if snapshot_remove_before(snapshotconf):
                if snapshot_remove(snapshotconf):
                    state.remove(snapshotconf)
    return state


def get_state(statelocation):
    """
    We need a state file to save and maintain the snapshots made previously.
    The state file is a pickled dict with all the information of a snapshot,
    including the config of that snapshot and the expiration time
    :param statelocation:   The location where to get the state file
    :return: a dict with the state
    """
    statelist = []
    if os.path.isfile(statelocation):
        try:
            with open(statelocation, 'rb') as f:
                statelist = pickle.load(f)
            logger.info("Found {} snapshots in state file".format(len(statelist)))
        except pickle.UnpicklingError:
            logger.error("Encountered an error unpickling the state file, please manually check existing snapshots")
        except (IOError, OSError) as e:
            logger.error("Could not open state file for reading: {}".format(e))
        except EOFError:
            logger.warning("Empty state dir found")
        return statelist
    else:
        logger.warn("No state file found at file \"{}\", is this the first run?".format(statelocation))
        return statelist


def save_state(statelocation, state):
    """
    :param statelocation:   The location where to save the state file
    :param state:           The dict to pickle and save
    :return: None
    """
    if NOOP:
        return
    try:
        with open(statelocation, 'wb') as f:
            pickle.dump(state, f)
    except pickle.PickleError:
        logger.error("Encountered an error pickling to the state file")
    except (IOError, OSError) as e:
        logger.error("Could not open state file for writing: {}".format(e))


def lock(locking_file):
    """
    Try to acquire a lock on the file to prevent multiple lvmsnapper instances
    :param locking_file: A path to the lock file
    :return: True if lock acquired
    """
    fp = open(locking_file, 'w')
    try:
        fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        return False
    return True

if __name__ == "__main__":
    global logger

    logger = logging.getLogger(__name__)
    stdout_log = logging.StreamHandler()
    stdout_log.setLevel(logging.DEBUG)
    syslog_log = handlers.SysLogHandler(facility=handlers.SysLogHandler.LOG_SYSLOG, address='/dev/log')
    syslog_log.setLevel(logging.DEBUG)
    logger.addHandler(stdout_log)
    logger.addHandler(syslog_log)

    # Parse config, report errors
    config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    if CONFIGFILE not in config.read(CONFIGFILE):
        print("Config file not found at: {}".format(CONFIGFILE))
        exit(1)

    # Check if we should run
    enabled = False
    try:
        # sysloglog.setLevel(loglevels[config['logging']['loglevel'].lower()])
        enabled = config.getboolean('main', 'enabled')
    except configparser.NoOptionError:
        pass
    if not enabled:
        logger.error("Not configure to run, exiting")
        exit(0)

    lock_file = None
    try:
        lock_file = config.get('main', 'lock_file')
    except configparser.NoOptionError:
        logger.error("No lock file config option found in the config file.")
        inc_errors()
    if not os.path.isabs(lock_file):
        logger.error("Specified lock file is not an absolute path to a file")
        inc_errors()

    logger.debug("starting config parser")
    # set correct loglevel as soon as possible
    try:
        # sysloglog.setLevel(loglevels[config['logging']['loglevel'].lower()])
        logger.setLevel(loglevels[config['logging']['loglevel'].lower()])
    except KeyError:
        logger.warn("No loglevel found in config, maintaining default loglevel")
    logger.debug("starting config parser")

    statefile = None
    # state file checking
    try:
        statefile = config['main']['statefile']
        if not check_statefile(statefile):
            logger.error("Invalid state file supplied in config")
            inc_errors()
    except KeyError:
        logger.error("No statefile found in main section of the config")
        inc_errors()

    expiration_conf = get_expires(config)
    snap_conf = get_snapdirs(config)

    if errors:
        logger.critical("Found {} error(s) in config, exiting".format(errors))
        exit(1)

    # check for the lock file
    if lock(lock_file):

        cur_time = datetime.utcnow()
        expire_time = get_longest_expire(expiration_conf, cur_time)
        if not expire_time:
            logger.info("No matching expiration, nothing to do")
            exit(0)
        logger.info("Snapshot expiration for this run is: {}".format(expire_time))

        state = get_state(statefile)

        state = create_all_snapshots(snap_conf, expire_time, cur_time, state)
        state = remove_expired(state, cur_time)
        save_state(statefile, state)
    else:
        logger.error("Could not acquire lock, exiting")
        exit(1)
