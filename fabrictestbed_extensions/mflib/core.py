# MIT License
#
# Copyright (c) 2022 FABRIC Testbed
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#


import json
import traceback
import os

from fabrictestbed_extensions.fablib.fablib import fablib
# For getting vars to make tunnel
from fabrictestbed_extensions.fablib.fablib import FablibManager

# from cryptography.hazmat.primitives import serialization as crypto_serialization
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.backends import default_backend as crypto_default_backend
# from os import chmod

import string
import random
#import paramiko

import logging

class Core():
    """
    MFLib core contains the core methods needed to create and interact with the Measurement Framework installed in a slice.
    It is not intended to be used by itself, but rather, it is the base object for creating Measurement Framework Library objects.
    """

    core_sanity_version = "1.0.22"
    """
    An updatable version for debugging purposes to make sure the correct version of this file is being used. Anyone can update this value as they see fit.
    Should always be increasing.

    Returns:
        String: Version.sub-version.build
    """

    logging_level = logging.INFO
    log_filename = ""
    
    # logging.info(f"Using core_sanity_version {core_sanity_version}")
    # logging.basicConfig(filename=log_file_path, format='%(asctime)s %(name)-8s %(levelname)-8s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level="INFO", force=True)
    # logging.info(f"-----Set slice name {value}.-----")

    core_logger = logging.getLogger()
# logging.exception
#loggers
    def set_core_logger(self, filename=None):
        """
        Sets up the core logging file. If filename is given, then log is saved to that filename. Otherwise filename is created from the self.logging_filename.
        Note that the self.logging_filename will be set with the slice when the slice name is set.
        Args:
            filename (_type_, optional): _description_. Defaults to None.
        """
        self.core_logger = logging.getLogger(__name__)
        self.core_logger.setLevel(self.logging_level)
        
        formatter = logging.Formatter('%(asctime)s %(name)-8s %(levelname)-8s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
        #, level="INFO", force=True)
        #logging.basicConfig(filename=log_file_path, format='%(asctime)s %(name)-8s %(levelname)-8s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level="INFO", force=True)
        
        if filename:
            self.log_filename = filename

        file_handler = logging.FileHandler(self.log_filename)
        file_handler.setLevel(self.logging_level)
        file_handler.setFormatter(formatter)

        self.core_logger.addHandler(file_handler)

    @property
    def slice_name(self):
        """
        Returns the name of the slice associated with this object.

        Returns:
            String: The name of the slice.
        """
        return self._slice_name 

    @slice_name.setter
    def slice_name( self, value ):
        """
        Sets the name of the slice associated with this object. Also creates the directories used to store local informations for mflib about the slice.
        Generally should not be called directly.
        Args:
            value (str): Name of the slice
        """
        # Set the slice name
        self._slice_name = value 

        # Create the local slice directory
        try:
            os.makedirs(self.local_slice_directory)
            os.makedirs(self.log_directory)
            self.log_filename = os.path.join(self.log_directory, "mflib.log")

            self.set_core_logger(filename=self.log_filename)

            self.core_logger.info(f"Using core_sanity_version {self.core_sanity_version}")
            self.core_logger.basicConfig(filename=self.log_filename, format='%(asctime)s %(name)-8s %(levelname)-8s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level="INFO", force=True)
            self.core_logger.info(f"-----Set slice name {value}.-----")

        except FileExistsError:
            pass 
            # Don't care if the file already exists.

    @property
    def local_slice_directory(self):
        """
        The directory where local files associated with the slice are stored.

        Returns:
            str: The directory where local files associated files are stored.
        """
        return os.path.join(self.local_storage_directory, self.slice_name)

    @property
    def log_directory(self):
        """
        The full path for the log directory.

        Returns:
            String: The full path to the log directory.
        """
        return os.path.join(self.local_slice_directory, "log")
        
    @property 
    def bootstrap_status_file(self):
        """
        The full path to the local copy of the bootstrap status file.

        Returns:
            String: The full path tp the local copy of the bootsrap status file.
        """
        return os.path.join(self.local_slice_directory, "bootstrap_status.json")

    @property 
    def common_hosts_file(self):
        """
        The full path to a local copy of the hosts.ini file. 

        Returns:
            String: The full path to a local copy of the hosts.ini file.
        """
        return os.path.join(self.local_slice_directory, "hosts.ini")    

    @property 
    def local_mfuser_private_key_filename(self):
        return os.path.join(self.local_slice_directory, "mfuser_private_key")    

    @property 
    def local_mfuser_public_key_filename(self):
        return os.path.join(self.local_slice_directory, "mfuser_pubic_key")    

    @property
    def meas_node(self):
        """
        The fablib node object for the Measurement Node in the slice.

        Returns:
            fablib.node: The fablib node object for the Measurement Node in the slice.

        """
        if self._meas_node:
            return self._meas_node 
        else:
            self._find_meas_node()
            return self._meas_node 
            
    @property
    def meas_node_ip(self):
        if self.meas_node:
            return self._meas_node.get_management_ip() 
        else:
            return ""

    @property
    def slice_username(self):
        if self.meas_node:
            return self._meas_node.get_username() 
        else:
            return ""

    @property
    def tunnel_host(self):
        """
        If a tunnel is used, this value must be set for the localhost, Otherwise it is set to empty string."""
        return self._tunnel_host
        
    @tunnel_host.setter
    def tunnel_host(self, value):
        """ 
        Set to "localhost" if using tunnnel.
        """
        self._tunnel_host = value
        

    @property
    def grafana_tunnel_local_port(self):
        """
        If a tunnel is used, this value must be set for the port"""
        return self._grafana_tunnel_local_port
        
    @grafana_tunnel_local_port.setter
    def grafana_tunnel_local_port(self, value):
        """ 
        Set to port_number if using tunnnel.
        """
        self._grafana_tunnel_local_port = value
        

    @property
    def kibana_tunnel_local_port(self):
        """
        If a tunnel is used, this value must be set for the port"""
        return self._kibana_tunnel_local_port
        
    @kibana_tunnel_local_port.setter
    def kibana_tunnel_local_port(self, value):
        """ 
        Set to port_number if using tunnnel.
        """
        self._kibana_tunnel_local_port = value
                

    # Tunnels are needed to access the meas node via the bastion host
    # In the future these may be combinded into one port with diff nginx paths mappings.
    # alt copy is a selection added to the fabric_rc file for setting a alertnate location for the files 
    #   such as on a laptop. This makes it easy to create a tunnel on a users laptop where they will need access
    #   to the web uis. 

    @property
    def grafana_tunnel(self):
        return self._meas_node_ssh_tunnel(local_port = self.grafana_tunnel_local_port, remote_port="443")

    @property
    def kibana_tunnel(self):
        return self._meas_node_ssh_tunnel(local_port = self.kibana_tunnel_local_port, remote_port="80")

    def _meas_node_ssh_tunnel(self, local_port, remote_port):
        """
        Returns the SSH tunnel command for accessing the meas node via bastion host.
        """

        slice_username = self.slice_username
        meas_node_ip = self.meas_node_ip
        
        # User has setup an ssh config file
        extra_fm = FablibManager()
        errmsg = ""
        ssh_config = ""
        private_key_file = ""
    
        extra_fm_vars = extra_fm.read_fabric_rc(extra_fm.default_fabric_rc)
        if extra_fm_vars:
            if "FABRIC_ALT_COPY_SSH_CONFIG" in extra_fm_vars:
                ssh_config = extra_fm_vars["FABRIC_ALT_COPY_SSH_CONFIG"]
            else:
                errmsg += "FABRIC_ALT_COPY_SSH_CONFIG not found in fabric_rc file. "

            if "FABRIC_ALT_COPY_SLICE_PRIVATE_KEY_FILE" in extra_fm_vars:
                private_key_file = extra_fm_vars["FABRIC_ALT_COPY_SLICE_PRIVATE_KEY_FILE"]
            else:
                errmsg += "FABRIC_ALT_COPY_SLICE_PRIVATE_KEY_FILE not found in fabric_rc file. "
            
        if errmsg:
            return "It appears you have not added alternate ssh config or slice key file locations to the fabric_rc file. " + errmsg
        else:
            #return f'ssh -L 10010:localhost:443 -F {extra_fm_vars["FABRIC_ALT_SSH_CONFIG"]} -i {extra_fm_vars["FABRIC_ALT_SLICE_PRIVATE_KEY_FILE"]} {self.slice_username}@{self.meas_node_ip}'
            tunnel_cmd = f'ssh -L {local_port}:localhost:{remote_port} -F {ssh_config} -i {private_key_file} {slice_username}@{meas_node_ip}'
            return tunnel_cmd 





    # Repo branch made class varible so it can be set before creating object
    mf_repo_branch = "main"
    
  
    def __init__(self, local_storage_directory="/tmp/mflib"):
        """
        Constructor.
        """
        #super().__init__()
        self.set_core_logger(os.path.join(local_storage_directory, "mflib_core.log"))
        self.core_logger.info("Creating mflib object.")
        
        #self.mf_repo_branch = "dev"
        self.tunnel_host = "localhost"
        self.grafana_tunnel_local_port = "10010"
        self.kibana_tunnel_local_port = "10020"


        # The slice_name
        self._slice_name = ""
        # The slice object
        self.slice = None
        # The meas_node object
        self._meas_node = None 

        # The following are normally constant values
        # Name given to the meas node
        self.measurement_node_name = "_meas_node"
        # Services directory on meas node
        self.services_directory = os.path.join("/", "home", "mfuser", "services")
        # Base names for keys
        self.mfuser_private_key_filename = "mfuser_private_key"
        self.mfuser_public_key_filename = "mfuser_public_key"

        try:
            self.local_storage_directory = local_storage_directory
            os.makedirs(self.local_storage_directory)
        except FileExistsError:
            pass

# IPV6 to IPV4 only sites fix
# note: should set bootstrap status file when making these 2 calls, status should be set, restored, not needed.
    def set_DNS_all_nodes(self):
        # Check if we need to
        if(self.meas_node.validIPAddress(self.meas_node.get_management_ip())=="IPv6"):
            for node in self.slice.get_nodes():
                self.set_DNS(node)
            return "set"
        else:
            return "not needed"

    def restore_DNS_all_nodes(self):
        # Check if we need to
        if(self.meas_node.validIPAddress(self.meas_node.get_management_ip())=="IPv6"):
            for node in self.slice.get_nodes():
                self.restore_DNS(node)
            return "restored"
        else:
            return "not needed"

    def set_DNS(self,node):
        if(node.validIPAddress(node.get_management_ip())=="IPv6"):
            node.execute("""
            printf 'nameserver 2a00:1098:2c::1\nnameserver 2a01:4f8:c2c:123f::1\nnameserver 2a01:4f9:c010:3f02::1' > resolv.new;
            sudo mv /etc/resolv.conf /etc/resolv.old;
            sudo mv resolv.new /etc/resolv.conf;
            """)
            #Needed for fedora
            node.execute("""
                sudo resolvectl dns eth0 2a00:1098:2c::1;
                sudo resolvectl dns eth0 2a01:4f8:c2c:123f::1;
                sudo
                resolvectl dns eth0 2a01:4f9:c010:3f02::1;
            """)
            # TODO add error checking


    def restore_DNS(self,node):
        if(node.validIPAddress(node.get_management_ip())=="IPv6"):
            node.execute("""
                sudo mv /etc/resolv.old /etc/resolv.conf;
            """)

            node.execute("""
                resolvectl revert eth0;
            """)








          
# User Methods 
    def create(self, service, data=None, files=[]):
        """
        Creates a new service for the slice. 
        :param service: The name of the service.
        :type service: String
        :param data: Data to be passed to a JSON file place in the service's meas node directory.
        :type data: JSON serializable object.
        :param files: List of filepaths to be uploaded.
        :type files: List of Strings
        """
        return self._run_on_meas_node(service, "create", data, files)

    def update(self, service, data=None, files=[]):
        """
        Updates an existing service for the slice.
        :param service: The name of the service.
        :type service: String
        :param data: Data to be passed to a JSON file place in the service's meas node directory.
        :type data: JSON serializable object.
        :param files: List of filepaths to be uploaded.
        :type files: List of Strings
        """
        return self._run_on_meas_node(service, "update", data, files)

    def info(self, service, data=None):
        """
        Gets inormation from an existing service. Strictly gets information, does not change how the service is running.
        :param service: The name of the service.
        :type service: String
        :param data: Data to be passed to a JSON file place in the service's meas node directory.
        :type data: JSON serializable object.
        """
        return self._run_on_meas_node(service, "info", data)

    def start(self, services=[]):
        """
        Restarts a stopped service using existing configs on meas node.
        """
        for service in services:
            return self._run_on_meas_node(service, "start")

    def stop(self, services=[]):
        """
        Stops a service, does not remove the service, just stops it from using resources.
        """
        for service in services:
            return self._run_on_meas_node(service, "stop")

    def status(self, services=[]):
        """
        Deprecated?, use info instead?
        Returns predefined status info. Does not change the running of the service.
        """ 
        for service in services:
            return self._run_on_meas_node(service, "status")

    def remove(self, services=[]):
        """
        Stops a service running and removes anything setup on the experiment's nodes. Service will then need to be re-created using the create command before service can be started again.
        """
        for service in services:
            return self._run_on_meas_node(service, "remove")



# Utility Methods

    def _upload_mfuser_keys(self, private_filename=None, public_filename=None):
        """
        Uploads the mfuser keys to the default user for easy access later.
        """
        if  private_filename is None:
            private_filename=self.local_mfuser_private_key_filename
        if  public_filename is None:
            public_filename=self.local_mfuser_public_key_filename

        try:
            local_file_path = private_filename
            remote_file_path = self.mfuser_private_key_filename
            stdout, stderr = self.meas_node.upload_file(local_file_path, remote_file_path) #, retry=3, retry_interval=10):

        except TypeError:
            pass 
            # TODO set file permissions on remote
            # This error is happening due to the file permmissions not being correctly set on the remote?
        except Exception as e:
            print(f"Failed Private Key Upload: {e}")

        try:
            local_file_path = public_filename
            remote_file_path = self.mfuser_public_key_filename
            stdout, stderr = self.meas_node.upload_file(local_file_path, remote_file_path) #, retry=3, retry_interval=10):
        except TypeError:
            pass 
            # TODO set file permissions on remote
            # This error is happening due to the file permmissions not being correctly set on the remote?   
            # Errors are:
            # Failed Private Key Upload: cannot unpack non-iterable SFTPAttributes object
            # Failed Public Key Upload: cannot unpack non-iterable SFTPAttributes object     
        except Exception as e:
            print(f"Failed Public Key Upload: {e}")


        # Set the permissions correctly on the remote machine.
        cmd = f"chmod 644 {self.mfuser_public_key_filename}"
        self.meas_node.execute(cmd)
        cmd = f"chmod 600 {self.mfuser_private_key_filename}"
        self.meas_node.execute(cmd)
        
    def _copy_mfuser_keys_to_mfuser_on_meas_node(self):
        """
        Copies mfuser keys from default location to mfuser .ssh folder and sets ownership & permissions.
        """
        try:
            cmd = f"sudo cp {self.mfuser_public_key_filename} /home/mfuser/.ssh/{self.mfuser_public_key_filename}; sudo chown mfuser:mfuser /home/mfuser/.ssh/{self.mfuser_public_key_filename}; sudo chmod 644 /home/mfuser/.ssh/{self.mfuser_public_key_filename}"
            stdout, stderr = self.meas_node.execute(cmd)
        
            print(stdout)
            print(stderr)

            cmd = f"sudo cp {self.mfuser_private_key_filename} /home/mfuser/.ssh/{self.mfuser_private_key_filename}; sudo chown mfuser:mfuser /home/mfuser/.ssh/{self.mfuser_private_key_filename}; sudo chmod 600 /home/mfuser/.ssh/{self.mfuser_private_key_filename}"
            stdout, stderr = self.meas_node.execute(cmd)

            print(stdout)
            print(stderr)
        except Exception as e:
            print(f"Failed mfuser key user key copy: {e}")
            return False 
        return True


    def _download_mfuser_keys(self, private_filename=None, public_filename=None):
        """
        Downloads the mfuser keys.
        """
        if  private_filename is None:
            private_filename=self.local_mfuser_private_key_filename
        if  public_filename is None:
            public_filename=self.local_mfuser_public_key_filename
        

        try:
            local_file_path = private_filename
            remote_file_path = self.mfuser_private_key_filename
            stdout, stderr = self.meas_node.download_file(local_file_path, remote_file_path) #, retry=3, retry_interval=10):

            local_file_path = public_filename
            remote_file_path = self.mfuser_public_key_filename
            stdout, stderr = self.meas_node.download_file(local_file_path, remote_file_path) #, retry=3, retry_interval=10):
            
        except Exception as e:
            print(f"Download mfuser Keys Failed: {e}")


    def _find_meas_node(self):
        """
        Finds the node named "meas" in the slice and sets the value for class's meas_node
        :return: If node found, sets self.meas_node and returns True. If node not found, clears self.meas_node and returns False.
        :rtype: Boolean
        """
        try:
            for node in self.slice.get_nodes():
                if node.get_name() == self.measurement_node_name:
                    self._meas_node = node 
                    return True 
        except Exception as e:
            print(f"Find Measure Node Failed: {e}")
        self._meas_node = None
        return False

        
    def _run_on_meas_node(self, service, command, data=None, files=[]):
        """
        Runs a command on the meas node.
        :param service: The name of the service.
        :type service: String
        :param command: The name of the command to run.
        :type command: String
        :param data: Data to be passed to a JSON file place in the service's meas node directory.
        :type data: JSON serializable object.
        :param files: List of filepaths to be uploaded.
        :type files: List of Strings
        :return: The stdout & stderr values from running the command ? Reformat to dict??
        :rtype: String ? dict??
        """
        # upload resources 
        if data:
            self._upload_service_data(service, data)
        else:
            # Ensure old stale data is remove on meas node
            self._upload_service_data(service, {})
        if files:
            self._upload_service_files(service, files)

        # run command 
        return self._run_service_command(service, command )

        
    def _upload_service_data(self, service, data):
        """
        Uploads the json serializable object data to a json file on the meas node.
        :param service: The service to which the data belongs.
        :type service: String
        :param data: A JSON serializable dictionary 
        :type data: dict
        """
        
            
        letters = string.ascii_letters
        try:
            # Create temp file for serialized json data
            randdataname = "mf_service_data_" + "".join(random.choice(letters) for i in range(10))
            local_file_path = os.path.join("/tmp", randdataname)
            with open(local_file_path, 'w') as datafile:
                #print("dumping data")
                json.dump(data, datafile)
            
            # Create remote filenames
            final_remote_file_path = os.path.join(self.services_directory, service, "data", "data.json")
            remote_tmp_file_path = os.path.join("/tmp", randdataname)
    
            # upload file
            fa = self.meas_node.upload_file(local_file_path, remote_tmp_file_path)
            
            # mv file to final location
            cmd = f"sudo mv {remote_tmp_file_path} {final_remote_file_path};  sudo chown mfuser:mfuser {final_remote_file_path}"
            
            self.meas_node.execute(cmd)
            
            # Remove local temp file.
            os.remove(local_file_path)
            
        except Exception as e:
            print(f"Service Data Upload Failed: {e}")  
            return False
        return True


    def _upload_service_files(self, service, files):
        """
        Uploads the given local files to the given service's directory on the meas node.
        :param service: Service name for which the files are being upload to the meas node.
        :type service: String
        :param files: List of file paths on local machine.
        :type files: List
        :raises: Exception: for misc failures....
        :return: ?
        :rtype: ?
        """
        letters = string.ascii_letters

        # TODO could add option to upload a directory of files using fablib.upload_directory
        try:
            for file in files:
                # Set src/dst filenames
                # file is local path
                local_file_path = file 
                filename = os.path.basename(file)
                final_remote_file_path = os.path.join(self.services_directory, service, "files", filename)

                randfilename = "mf_file_" + "".join(random.choice(letters) for i in range(10))
                remote_tmp_file_path = os.path.join("/tmp", randfilename)
                
                # upload file
                fa = self.meas_node.upload_file(local_file_path, remote_tmp_file_path) # retry=3, retry_interval=10, username="mfuser", private_key="mfuser_private_key")
                cmd = f"sudo mv {remote_tmp_file_path} {final_remote_file_path};  sudo chown mfuser:mfuser {final_remote_file_path}; sudo rm {remote_tmp_file_path}"
 
                self.meas_node.execute(cmd)

        except Exception as e:
            print(f"Service File Upload Failed: {e}")
            return False
        return True


    def _run_service_command( self, service, command ):
        """
        Runs the given comand for the given service on the meas node. 
        :param service: Service name for which the command is being run on the meas node.
        :type service: String
        :param files: Command name.
        :type files: String
        :raises: Exception: for misc failures....
        :return: Resulting output? JSON output or dictionary?
        :rtype: ?
        """

        try:
            full_command = f"sudo -u mfuser python3 {self.services_directory}/{service}/{command}.py"
            stdout, stderr = self.meas_node.execute(full_command) #retry=3, retry_interval=10, username="mfuser", private_key="mfuser_private_key"
        except Exception as e:
            print(f"Service Commnad Run Failed: {e}")
#         print(type(stdout))
#         print(stdout)
#         print(stderr)
        try:
            # Convert the json string to a dict
            jsonstr = stdout
            # remove non json string
            jsonstr = jsonstr[ jsonstr.find('{'):jsonstr.rfind('}')+1]
            # Need to "undo" what the exceute command did
            jsonstr = jsonstr.replace('\n','\\n')
            #print(jsonstr)
            ret_data = json.loads(jsonstr)
            return ret_data
            # TODO add stderr to return value?
        except Exception as e:
            print("Unable to convert returned comand json.")
            print("STDOUT: ")
            print(stdout)
            print("STDERR: ")
            print(stderr)
            print(f"Fail: {e}")
        return {} #(stdout, stderr)


    def _download_service_file(self, service, filename, local_file_path=""):
        """
        Downloads service files from the meas node and places them in the local storage directory.
        :param service: Service name
        :type service: String
        :param filename: The filename to download from the meas node.
        :param local_file_path: Optional filename for local saved file. If not given, file will be in default slice directory.# Fri Sep 09 2022 14:30
        :type local_file_path: String
        """

        if not local_file_path:
            local_file_path = os.path.join(self.local_slice_directory, service, filename)
            # ensure local directory exists
            local_dir_path = os.path.dirname(local_file_path) 
            if not os.path.exists(local_dir_path):
                os.makedirs(local_dir_path)

        # 
        #  Download a file from a service directory
        # Probably most useful for grabbing output from a command run.
        # TODO figure out how to name/where to put file locally
        try:
            #local_file_path = os.path.join(self.local_slice_directory, service, filename)
            remote_file_path = os.path.join(self.services_directory, service, filename)
            file_attributes = self.meas_node.download_file(local_file_path, remote_file_path) #, retry=3, retry_interval=10):
            return {"success":True, "filename":local_file_path}
        except Exception as e:
            print(f"Download service file Fail: {e}")
            return {"success":False}
        
        
    def _clone_mf_repo(self):
        """
        Clone the repo to the mfuser on the meas node.|
        """
        cmd = f"sudo -u mfuser git clone -b {self.mf_repo_branch} https://github.com/fabric-testbed/MeasurementFramework.git /home/mfuser/mf_git"
        stdout, stderr = self.meas_node.execute(cmd)
        self.core_logger.info(f"Cloned MeasurementFramework branch {self.mf_repo_branch} to measure node.")
        self.core_logger.info(stdout)
        self.core_logger.info(stderr)
        
    def _run_bootstrap_script(self):
        """
        Run the initial bootstrap script in the meas node mf repo.
        """
        cmd = f'sudo -u mfuser /home/mfuser/mf_git/instrumentize/experiment_bootstrap/bootstrap.sh'
        stdout, stderr = self.meas_node.execute(cmd)
        
        self.core_logger.info(f"bootstrap bash script ran on measure node.")
        self.core_logger.info(stdout)
        self.core_logger.info(stderr)

        print("Bootstrap script done")

    def _run_bootstrap_ansible(self):
        """
        Run the initial bootstrap ansible scripts in the meas node mf repo.
        """
        cmd = f'sudo -u mfuser python3 /home/mfuser/mf_git/instrumentize/experiment_bootstrap/bootstrap_playbooks.py'
        stdout, stderr = self.meas_node.execute(cmd)
        
        self.core_logger.info(f"bootstrap ansible script ran on measure node.")
        self.core_logger.info(stdout)
        self.core_logger.info(stderr)


        print("Bootstrap ansible scripts done")
        

    ############################
    # Calls made as slice user
    ###########################
    def get_bootstrap_status(self, force=True):
        """
        Returns the bootstrap status for the slice. Default setting of force will always download the most recent file from the meas node.
        :param force: If downloaded file already exists locally, it will not be downloaded unless force is True. The downloaded file will be stored locally for future reference. 
        :return: Bootstrap dict if any type of bootstraping has occured, None otherwise. 
        :rtype: dict
        """
        if force or not os.path.exists(self.bootstrap_status_file):
            if not self._download_bootstrap_status():
                #print("Bootstrap file was not downloaded. Bootstrap most likely has not been done.")
                return {}
        
            
        if os.path.exists(self.bootstrap_status_file):
            with open(self.bootstrap_status_file) as bsf:
                try:
                    bootstrap_dict = json.load(bsf)
                    print(bootstrap_dict)
                    if bootstrap_dict:
                        return bootstrap_dict 
                    else:
                        return {}
                except Exception as e:
                    print(f"Bootstrap failed to decode")
                    print(f"Fail: {e}")
                    return {}
        else:
            return {}


    def _download_bootstrap_status(self):
        """
        Downloaded file will be stored locally for future reference.  
        :return: True if bootstrap file downloaded, False otherwise. 
        :rtype: Boolean # or maybe just the entire json?
        """
        try:
            local_file_path = self.bootstrap_status_file
            remote_file_path =  os.path.join("bootstrap_status.json")
            #print(local_file_path)
            #print(remote_file_path)
            file_attributes = self.meas_node.download_file(local_file_path, remote_file_path, retry=1) #, retry=3, retry_interval=10): # note retry is really tries
            #print(file_attributes)
            
            return True
        except FileNotFoundError:
            pass 
            # Most likely the file does not exist because it has not yet been created. So we will ignore this exception.
        except Exception as e:
            print("Bootstrap download has failed.")
            print(f"Fail: {e}")
            return False
        return False  
    
    
    
    def get_mfuser_private_key(self, force=True):
        """
        Returns the mfuser private key. Default setting of force will always download the most recent file from the meas node.
        :param force: If downloaded file already exists locally, it will not be downloaded unless force is True. The downloaded file will be stored locally for future reference. 
        :return: True if file is found, false otherwise. 
        :rtype: Boolean
        """
        if force or not os.path.exists(self.local_mfuser_private_key_filename):
            self._download_mfuser_private_key()

        if os.path.exists(self.local_mfuser_private_key_filename):
                return True 
        else:
            return False 


    def _download_mfuser_private_key(self):
        """
        Downloaded file will be stored locally for future reference.  
        :return: True if key file downloaded, False otherwise. 
        :rtype: Boolean
        """
        try:
            local_file_path = self.local_mfuser_private_key_filename
            remote_file_path =  self.mfuser_private_key_filename
            file_attributes = self.meas_node.download_file(local_file_path, remote_file_path) #, retry=3, retry_interval=10):
            #print(file_attributes)
            return True
        except Exception as e:
            print(f"Download mfuser private key Failed: {e}")
        return False  
    
    
    def _update_bootstrap(self, key, value):
        """
        Updates the given key to the given value in the bootstrap_status.json file on the meas node.
        """
        bsf_dict = self.get_bootstrap_status()
        #self.download_bootstrap_status()
        #bsf_dict = {}
        bsf_dict[key] = value
        
        with open(self.bootstrap_status_file, "w") as bsf:
            json.dump(bsf_dict, bsf)
    
        try:
            local_file_path = self.bootstrap_status_file
            remote_file_path =  os.path.join("bootstrap_status.json")
            #print(local_file_path)
            #print(remote_file_path)
            file_attributes = self.meas_node.upload_file(local_file_path, remote_file_path) #, retry=3, retry_interval=10):
            #print(file_attributes)
            
            return True

        except Exception as e:
            print("Bootstrap upload has failed.")
            print(f"Fail: {e}")
        return False  
    
       
    
    def download_log_file(self, service, method):
        """
        Download the log file for the given service and method.
        Downloaded file will be stored locally for future reference. 
        :param service: The name of the service.
        :type service: String 
        :param method: The method name such as create, update, info, start, stop, remove.
        :type method: String
        :return: Writes file to local storage and returns text of the log file.
        :rtype: String
        """
        try:
            local_file_path = os.path.join( self.local_slice_directory, f"{method}.log")
            remote_file_path =  os.path.join("/","home","mfuser","services", service, "log", f"{method}.log")
            #print(local_file_path)
            #print(remote_file_path)
            file_attributes = self.meas_node.download_file(local_file_path, remote_file_path, retry=1) #, retry=3, retry_interval=10): # note retry is really tries
            #print(file_attributes)
            
            with open(local_file_path) as f:
                log_text = f.read()
                return local_file_path, log_text

        except Exception as e:
            print("Service log download has failed.")
            print(f"Downloading service log file has Failed. It may not exist: {e}")
            return "",""

    
