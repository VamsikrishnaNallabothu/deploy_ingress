from tools.resolve_config_references import ResolveReferences as RR
from tools.utilities.secrets_manager.secrets_fetcher import CredentialsProvider as CP
from tools.common_rest_ops import RestOperations as RO
from tools.round_robin import RoundRobin as RORO
from tools.logger import Logger
from collections import OrderedDict as OD
from configobj import ConfigObj as CO
import google.auth.transport.requests as reqs
from google.oauth2 import service_account
from google.cloud import bigquery
from googleapiclient import discovery
from google.cloud import billing_v1
from functools import wraps
from datetime import datetime as dt, timedelta as td
from dateutil.relativedelta import relativedelta as rd
from calendar import monthrange
import json
import sys
import os
import warnings
import time

# Author: Vamsi
# Date: 9/9/2020

warnings.filterwarnings('ignore')


class GetObject(object):
    """
    With this class, I will have the leverage to make a REST call to Compute Engine API only when called
    and not while fetching a list of items
    """
    def __init__(self, payload, rest_ops,  ret_json_obj=False):
        """
        :param: payload
        :param payload["url"]: uri
        :param ret_json_obj: bool: if set to True, returns a json object with execute function to call later
        :return: json or jsob_obj depending on ret_json_obj parameter
        """
        self.url = payload["url"]
        self.headers = payload["headers"]
        self.params = payload["params"]
        self.rest_ops = rest_ops
        self.ret_json_obj = ret_json_obj

    def get_object(self):
        payload = dict()
        payload["url"] = self.url
        payload["headers"] = self.headers
        # returns a json_object
        url_resp = self.rest_ops.get_query(payload=payload, ret_json_obj=self.ret_json_obj)

        class URLObject(object):
            def __init__(self, url_object):
                self.execute = url_object
        if self.ret_json_obj:
            url_resp_object = URLObject(url_object=url_resp)
            return url_resp_object
        else:
            return url_resp


# noinspection PyTypeChecker
class GoogleConnector(object):
    def __init__(self, config=None, logger=None):
        self.config, self.logger = self.get_config_logger(config=config, logger=logger)
        cloud_type = "GCP"
        self.cp_con = CP(cloud_type=cloud_type, config=self.config, logger=self.logger)
        if "USE_SM" in self.cp_con.cloud_config and self.cp_con.cloud_config.as_bool("USE_SM"):
            self.cp_con.sm_cls_obj.default_secrets_path = self.cp_con.sm_cls_obj.default_secrets_path + f"{cloud_type}/"
        self.cp_con.get_cloud_secrets()
        self.config["CLOUD"][cloud_type] = self.cp_con.cloud_config
        service_account_json_file = os.getenv("HOME") + self.config["CLOUD"]["GCP"]["CREDENTIAL_FILE"]
        scopes = ["https://www.googleapis.com/auth/cloud-platform",
                  "https://www.googleapis.com/auth/cloud-billing.readonly"]
        self.request = reqs.Request()
        self.credentials = service_account.Credentials.from_service_account_file(
            filename=service_account_json_file,
            scopes=scopes)
        self.access_token = self.get_access_token()
        self.project = self.credentials.project_id
        self.compute_client = discovery.build('compute', 'v1', credentials=self.credentials)
        self.billing_client = discovery.build('cloudbilling', 'v1', credentials=self.credentials)
        self.billing_client_v1 = billing_v1.CloudBillingClient(credentials=self.credentials)
        self.rest_ops = RO(logger=self.logger)
        self.headers = {"content-type": "application/json;charset=UTF-8", "authorization": self.access_token}
        self.compute_base_url = f"https://www.googleapis.com/compute/v1/projects/{self.project}/"

    @staticmethod
    def get_config_logger(config, logger):
        """
        :param config:
        :param logger:
        :return: configobj, logger_object
        """
        if config is None:
            config = CO(infile='config_files/infra_access.cfg')
            if logger is None:
                logger = Logger(log_filename=config["PERFORMANCE"]["LOG_FILE"])
                logger = logger.logger

            else:
                logger = logger
            cfg_rr = RR(config=config, logger=logger)
            config = cfg_rr.search_and_convert_references(config=config)
        else:
            if logger is None:
                logger = Logger(log_filename=config["PERFORMANCE"]["LOG_FILE"])
                logger = logger.logger
            else:
                logger = logger
        return config, logger

    def get_access_token(self):
        self.credentials.refresh(self.request)
        # print(self.credentials.token)
        token = 'Bearer ' + self.credentials.token
        self.headers = {"content-type": "application/json;charset=UTF-8", "authorization": token}
        return token

    # @staticmethod  # calling static method is not supported in python versions < 3.10
    #  Changed in version 3.10: Static methods now inherit the method attributes
    #  (module, name, qualname, doc and annotations), have a new wrapped attribute, and are now callable as regular
    #  functions.
    @staticmethod
    def access_token_validator(func):
        @wraps(func)
        def get_access_token(self, *args, **kwargs):
            self.logger.info("Checking Access Token Validity")
            if not self.credentials.valid:
                self.logger.warn("Access Token Invalid!! Refreshing Access Token")
                self.get_access_token()
            self.logger.info("Access Token Validity verified.")
            return func(self, *args, **kwargs)
        return get_access_token

    @access_token_validator
    def wait_on_operation(self, params, operation_type="global", iterations=3):
        """
        wait for the operation to complete
        :param params: dictionary containing: 'operation_id'
        :param operation_type: specify 'global' (default) or 'regional' or 'zonal' operation
        :param iterations: we wait for 2 mins(as per api definition) wait * iterations count - if status not done
        :return:
        """
        operation_id = params.get("operation_id", None)
        project = params.get("project", None)
        if project is None:
            project = self.project
        compute_base_url = f"https://www.googleapis.com/compute/v1/projects/{project}/"
        if operation_type == "regional":
            region = params.get("region", None)
            if region is None:
                self.logger.info(f"Params: {params} should contain parameter: 'region' for regional operation")
                sys.exit(1)
            else:
                url = f"{compute_base_url}regions/{region}/operations/{operation_id}/wait"
        elif operation_type == "zonal":
            zone = params.get("zone", None)
            if zone is None:
                self.logger.info(f"Params: {params} should contain parameter: 'zone' for a zonal operation")
                sys.exit(1)
            else:
                url = f"{compute_base_url}zones/{zone}/operations/{operation_id}/wait"
        else:
            # global operation
            url = f"{compute_base_url}global/operations/{operation_id}/wait"
        self.logger.info(f'Waiting for operation: {operation_id} to finish...')
        payload = dict()
        payload["url"] = url
        payload["headers"] = self.headers
        data = dict()
        payload["data"] = json.dumps(data)
        while iterations != 0:
            # returns json
            iterations -= 1
            resp = self.rest_ops.post_query(payload=payload).json()  # set timeout to more than api timeout (120)
            # status could always be one of these enum values: [PENDING, RUNNING,DONE], we want "DONE"
            if "error" in resp:
                self.logger.error("Operation Failed: Received Error")
                raise Exception(resp["error"])
            if resp["status"] == "DONE":
                self.logger.info(f"Request succeeded for Operation: {operation_id}")
                return True
            self.logger.info(f"Status: {resp['status']} - iterations left: {iterations}")
        self.logger.error(f"Wait iterations exceeded and status is still not 'DONE' for the operation: {operation_id}")
        return False

    def _compute_base_url_for_project(self, project=None):
        if project is None:
            project = self.project
        return f"https://www.googleapis.com/compute/v1/projects/{project}/"

    def _network_security_base_url(self, project=None, location="global"):
        if project is None:
            project = self.project
        return f"https://networksecurity.googleapis.com/v1/projects/{project}/locations/{location}/"

    def _build_network_self_link(self, vpc_name, project=None):
        compute_base_url = self._compute_base_url_for_project(project=project)
        return f"{compute_base_url}global/networks/{vpc_name}"

    def _build_subnet_self_link(self, subnet_name, region, project=None):
        compute_base_url = self._compute_base_url_for_project(project=project)
        return f"{compute_base_url}regions/{region}/subnetworks/{subnet_name}"

    def _get_config_section(self, section_names):
        for section_name in section_names:
            if section_name in self.config:
                return self.config[section_name]
        return None

    def _parse_cfg_value(self, value, default=None):
        if value is None:
            return default
        if isinstance(value, str):
            trimmed = value.strip()
            if (trimmed.startswith("{") and trimmed.endswith("}")) or \
               (trimmed.startswith("[") and trimmed.endswith("]")):
                try:
                    return json.loads(trimmed)
                except Exception:
                    return value
        return value

    def _load_nsi_inband_config(self):
        section = self._get_config_section([
            "GCP-NSI-INBAND",
            "GCP-NSI",
            "GCP-NSI_INBAND",
            "GCP-NSI-INBAND-CONSUMER"
        ])
        if section is None:
            return None
        cfg = dict()
        cfg["producer_cfg"] = self._parse_cfg_value(section.get("NSI_INBAND_PRODUCER_CFG", None), default=None)
        cfg["consumer_cfg"] = self._parse_cfg_value(section.get("NSI_INBAND_CONSUMER_CFG", None), default=None)
        cfg["nsi_cfg"] = self._parse_cfg_value(section.get("NSI_INBAND_NSI_CFG", None), default=None)
        cfg["vm_cfg"] = self._parse_cfg_value(section.get("NSI_INBAND_VM_CFG", None), default=None)
        cfg["override_existing_resources"] = section.as_bool("NSI_INBAND_OVERRIDE_EXISTING_RESOURCES") if \
            "NSI_INBAND_OVERRIDE_EXISTING_RESOURCES" in section else False
        cfg["delete_vpcs_on_cleanup"] = section.as_bool("NSI_INBAND_DELETE_VPCS_ON_CLEANUP") if \
            "NSI_INBAND_DELETE_VPCS_ON_CLEANUP" in section else False
        return cfg

    @access_token_validator
    def list_vpcs(self, project=None, query_filter=None):
        if project is None:
            project = self.project
        vpcs = {}
        request = self.compute_client.networks().list(project=project, filter=query_filter)
        while request is not None:
            response = request.execute()
            for network in response.get("items", []):
                vpcs[network["name"]] = network
            request = self.compute_client.networks().list_next(previous_request=request, previous_response=response)
        return vpcs

    def get_vpc(self, vpc_name, project=None):
        if project is None:
            project = self.project
        try:
            req = self.compute_client.networks().get(project=project, network=vpc_name)
            return req.execute()
        except Exception:
            return None

    def ensure_network_firewall_policy_order(self, vpc_name, project=None,
                                              desired_order="BEFORE_CLASSIC_FIREWALL",
                                              auto_fix=True, wait=True):
        if project is None:
            project = self.project
        network = self.get_vpc(vpc_name=vpc_name, project=project)
        if network is None:
            self.logger.error(f"Network not found for firewall policy order validation: {vpc_name}")
            sys.exit(1)
        current_order = network.get("networkFirewallPolicyEnforcementOrder", None)
        if current_order == desired_order:
            self.logger.info(f"Network firewall policy enforcement order already set: {desired_order}")
            return True
        self.logger.warning(f"Network firewall policy enforcement order is {current_order}. "
                            f"Expected: {desired_order}")
        if not auto_fix:
            self.logger.error("auto_fix is False; refusing to modify enforcement order. Exit!")
            sys.exit(1)
        patch_body = {"networkFirewallPolicyEnforcementOrder": desired_order}
        req = self.compute_client.networks().patch(project=project, network=vpc_name, body=patch_body)
        resp = req.execute()
        if 'error' in resp:
            raise Exception(resp["error"])
        if resp["status"] == "DONE":
            self.logger.info("Network firewall policy enforcement order updated successfully")
            return True
        if wait:
            if self.wait_on_operation(params={"operation_id": resp["id"], "project": project}):
                self.logger.info("Network firewall policy enforcement order updated successfully")
                return True
            self.logger.error("Failed to update network firewall policy enforcement order. Exit!")
            sys.exit(1)
        return False

    @access_token_validator
    def list_subnets(self, project=None, region=None, query_filter=None):
        if project is None:
            project = self.project
        subnets = []
        if region is None:
            request = self.compute_client.subnetworks().aggregatedList(project=project, filter=query_filter)
            while request is not None:
                response = request.execute()
                for region_items in response.get("items", {}).values():
                    subnets.extend(region_items.get("subnetworks", []))
                request = self.compute_client.subnetworks().aggregatedList_next(previous_request=request,
                                                                                previous_response=response)
        else:
            request = self.compute_client.subnetworks().list(project=project, region=region, filter=query_filter)
            while request is not None:
                response = request.execute()
                subnets.extend(response.get("items", []))
                request = self.compute_client.subnetworks().list_next(previous_request=request,
                                                                      previous_response=response)
        return subnets

    @access_token_validator
    def create_vpc(self, vpc_name, project=None, routing_mode="REGIONAL", auto_create_subnetworks=False,
                   description=None, wait=True, override_existing_resources=False):
        if project is None:
            project = self.project
        existing_vpcs = self.list_vpcs(project=project, query_filter=f"name={vpc_name}")
        if vpc_name in existing_vpcs:
            if not override_existing_resources:
                self.logger.info(f"VPC already exists: {vpc_name} in project: {project}")
                return existing_vpcs[vpc_name]
            self.logger.info(f"Override enabled. Deleting VPC: {vpc_name} in project: {project}")
            self.delete_vpc(vpc_name=vpc_name, wait=True, project=project)
        vpc_config = {"name": vpc_name,
                      "routingConfig": {"routingMode": routing_mode},
                      "autoCreateSubnetworks": auto_create_subnetworks}
        if description:
            vpc_config["description"] = description
        self.logger.info(f"Creating VPC: {vpc_name} in project: {project}")
        req = self.compute_client.networks().insert(project=project, body=vpc_config)
        resp = req.execute()
        if 'error' in resp:
            raise Exception(resp["error"])
        if resp["status"] == "DONE":
            self.logger.info(f"VPC: {vpc_name} creation successful")
            return resp
        operation_id = resp["id"]
        if wait:
            if self.wait_on_operation(params={"operation_id": operation_id, "project": project}):
                self.logger.info(f"VPC: {vpc_name} creation successful")
                return resp
            else:
                self.logger.error("VPC creation failed. Exit!")
                sys.exit(1)
        return resp

    @access_token_validator
    def create_vpcs(self, vpc_configs, override_existing_resources=False):
        """
        Create multiple VPCs with parallel operations.
        vpc_configs: list of dicts with keys: name, project, routing_mode, auto_create_subnetworks, description
        """
        operation_ids = []
        vpc_configs = vpc_configs or []
        vpcs_by_project = {}
        for cfg in vpc_configs:
            project = cfg.get("project", self.project)
            vpcs_by_project.setdefault(project, set())
        for project in vpcs_by_project:
            vpcs_by_project[project] = set(self.list_vpcs(project=project).keys())
        for cfg in vpc_configs:
            vpc_name = cfg["name"]
            project = cfg.get("project", self.project)
            if vpc_name in vpcs_by_project.get(project, set()):
                if not override_existing_resources:
                    self.logger.info(f"VPC already exists: {vpc_name} in project: {project}")
                    continue
                self.logger.info(f"Override enabled. Deleting VPC: {vpc_name} in project: {project}")
                self.delete_vpc(vpc_name=vpc_name, wait=True, project=project)
            vpc_config = {"name": vpc_name,
                          "routingConfig": {"routingMode": cfg.get("routing_mode", "REGIONAL")},
                          "autoCreateSubnetworks": cfg.get("auto_create_subnetworks", False)}
            if cfg.get("description"):
                vpc_config["description"] = cfg["description"]
            self.logger.info(f"Creating VPC: {vpc_name} in project: {project}")
            req = self.compute_client.networks().insert(project=project, body=vpc_config)
            resp = req.execute()
            if 'error' in resp:
                raise Exception(resp["error"])
            if resp["status"] != "DONE":
                operation_ids.append({"operation_id": resp["id"], "project": project})
        for params in operation_ids:
            if self.wait_on_operation(params=params):
                self.logger.info(f"VPC operation: {params['operation_id']} successful")
            else:
                self.logger.error(f"VPC operation: {params['operation_id']} failed. Exit!")
                sys.exit(1)
        return True

    @access_token_validator
    def create_subnet(self, subnet_name, region, ip_cidr_range, vpc_name=None, network=None, project=None,
                      enable_flow_logs=False, private_ip_google_access=True, secondary_ip_ranges=None, wait=True,
                      override_existing_resources=False):
        if project is None:
            project = self.project
        if network is None:
            if vpc_name is None:
                self.logger.error("Either vpc_name or network must be provided to create subnet")
                sys.exit(1)
            network = self._build_network_self_link(vpc_name=vpc_name, project=project)
        existing = self.list_subnets(project=project, region=region, query_filter=f"name={subnet_name}")
        if existing:
            if not override_existing_resources:
                self.logger.info(f"Subnet already exists: {subnet_name} in project: {project}, region: {region}")
                return existing[0]
            self.logger.info(f"Override enabled. Deleting subnet: {subnet_name} in project: {project}, region: {region}")
            self.delete_subnet(subnet_config={"name": subnet_name, "region": region}, wait=True, project=project)
        subnet_config = {"name": subnet_name,
                         "network": network,
                         "region": region,
                         "ipCidrRange": ip_cidr_range,
                         "enableFlowLogs": enable_flow_logs,
                         "privateIpGoogleAccess": private_ip_google_access,
                         "secondaryIpRanges": secondary_ip_ranges or []}
        self.logger.info(f"Creating subnet: {subnet_name} in project: {project}, region: {region}")
        req = self.compute_client.subnetworks().insert(project=project, region=region, body=subnet_config)
        resp = req.execute()
        if 'error' in resp:
            raise Exception(resp["error"])
        if resp["status"] == "DONE":
            self.logger.info(f"Subnet: {subnet_name} creation successful")
            return resp
        operation_id = resp["id"]
        if wait:
            if self.wait_on_operation(params={"operation_id": operation_id, "region": region, "project": project},
                                      operation_type="regional"):
                self.logger.info(f"Subnet: {subnet_name} creation successful")
                return resp
            else:
                self.logger.error("Subnet creation failed. Exit!")
                sys.exit(1)
        return resp

    @access_token_validator
    def create_subnets(self, subnet_configs, override_existing_resources=False):
        """
        Create multiple subnets with parallel operations.
        subnet_configs: list of dicts with keys: name, region, ip_cidr_range, vpc_name/network, project
        """
        operation_ids = []
        subnet_configs = subnet_configs or []
        for cfg in subnet_configs:
            project = cfg.get("project", self.project)
            region = cfg["region"]
            subnet_name = cfg["name"]
            existing = self.list_subnets(project=project, region=region, query_filter=f"name={subnet_name}")
            if existing:
                if not override_existing_resources:
                    self.logger.info(f"Subnet already exists: {subnet_name} in project: {project}, region: {region}")
                    continue
                self.logger.info(f"Override enabled. Deleting subnet: {subnet_name} in project: {project}, "
                                 f"region: {region}")
                self.delete_subnet(subnet_config={"name": subnet_name, "region": region}, wait=True, project=project)
            network = cfg.get("network", None)
            if network is None:
                vpc_name = cfg.get("vpc_name", None)
                if vpc_name is None:
                    self.logger.error("Either vpc_name or network must be provided in subnet config")
                    sys.exit(1)
                network = self._build_network_self_link(vpc_name=vpc_name, project=project)
            subnet_config = {"name": subnet_name,
                             "network": network,
                             "region": region,
                             "ipCidrRange": cfg["ip_cidr_range"],
                             "enableFlowLogs": cfg.get("enable_flow_logs", False),
                             "privateIpGoogleAccess": cfg.get("private_ip_google_access", True),
                             "secondaryIpRanges": cfg.get("secondary_ip_ranges", [])}
            self.logger.info(f"Creating subnet: {subnet_name} in project: {project}, region: {region}")
            req = self.compute_client.subnetworks().insert(project=project, region=region, body=subnet_config)
            resp = req.execute()
            if 'error' in resp:
                raise Exception(resp["error"])
            if resp["status"] != "DONE":
                operation_ids.append({"operation_id": resp["id"], "region": region, "project": project})
        for params in operation_ids:
            if self.wait_on_operation(params=params, operation_type="regional"):
                self.logger.info(f"Subnet operation: {params['operation_id']} successful")
            else:
                self.logger.error(f"Subnet operation: {params['operation_id']} failed. Exit!")
                sys.exit(1)
        return True

    def _nsi_get(self, url):
        payload = {"url": url, "headers": self.headers}
        return self.rest_ops.get_query(payload=payload)

    def _nsi_post(self, url, body):
        payload = {"url": url, "headers": self.headers, "data": json.dumps(body)}
        resp = self.rest_ops.post_query(payload=payload)
        return resp.json() if resp is not None else {}

    def _nsi_put(self, url, body):
        payload = {"url": url, "headers": self.headers, "data": json.dumps(body)}
        resp = self.rest_ops.put_query(payload=payload)
        return resp.json() if resp is not None and hasattr(resp, "json") else {}

    def _nsi_delete(self, url):
        payload = {"url": url, "headers": self.headers}
        resp = self.rest_ops.delete_query(payload=payload)
        return resp.json() if resp is not None else {}

    def _wait_on_nsi_operation(self, operation, timeout_seconds=600, poll_interval=5):
        if operation is None:
            return None
        if isinstance(operation, dict):
            op_name = operation.get("name", None)
        else:
            op_name = None
        if not op_name:
            return operation
        url = f"https://networksecurity.googleapis.com/v1/{op_name}"
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            resp = self._nsi_get(url)
            if isinstance(resp, dict) and resp.get("done", False):
                return resp
            time.sleep(poll_interval)
        self.logger.error(f"Timed out waiting for NSI operation: {op_name}")
        return None

    @staticmethod
    def _is_resource_not_found(resp):
        return isinstance(resp, dict) and resp.get("error", {}).get("code") == 404

    @staticmethod
    def _resource_exists(resp):
        return isinstance(resp, dict) and resp.get("name", None) is not None and "error" not in resp

    def _nsi_list(self, base_url, resource_path, items_key):
        items = []
        page_token = None
        while True:
            url = f"{base_url}{resource_path}"
            if page_token:
                url = f"{url}?pageToken={page_token}"
            resp = self._nsi_get(url)
            if isinstance(resp, dict):
                items.extend(resp.get(items_key, []))
                page_token = resp.get("nextPageToken", None)
                if not page_token:
                    break
            else:
                break
        return items

    def get_intercept_deployment_group(self, name, project=None, location="global"):
        base_url = self._network_security_base_url(project=project, location=location)
        return self._nsi_get(f"{base_url}interceptDeploymentGroups/{name}")

    def get_intercept_deployment(self, name, project=None, location="global"):
        base_url = self._network_security_base_url(project=project, location=location)
        return self._nsi_get(f"{base_url}interceptDeployments/{name}")

    def get_intercept_endpoint_group(self, name, project=None, location="global"):
        base_url = self._network_security_base_url(project=project, location=location)
        return self._nsi_get(f"{base_url}interceptEndpointGroups/{name}")

    def list_intercept_endpoint_groups(self, project=None, location="global"):
        base_url = self._network_security_base_url(project=project, location=location)
        return self._nsi_list(base_url=base_url, resource_path="interceptEndpointGroups",
                              items_key="interceptEndpointGroups")

    def get_intercept_endpoint_group_association(self, name, project=None, location="global"):
        base_url = self._network_security_base_url(project=project, location=location)
        return self._nsi_get(f"{base_url}interceptEndpointGroupAssociations/{name}")

    def list_intercept_endpoint_group_associations(self, project=None, location="global"):
        base_url = self._network_security_base_url(project=project, location=location)
        return self._nsi_list(base_url=base_url, resource_path="interceptEndpointGroupAssociations",
                              items_key="interceptEndpointGroupAssociations")

    def create_intercept_endpoint_group(self, name, intercept_deployment_group, project=None, location="global",
                                        description=None, labels=None, wait=True,
                                        override_existing_resources=False):
        base_url = self._network_security_base_url(project=project, location=location)
        existing = self.get_intercept_endpoint_group(name=name, project=project, location=location)
        if self._resource_exists(existing):
            if not override_existing_resources:
                self.logger.info(f"Intercept endpoint group already exists: {name}")
                return existing
            self.logger.info(f"Override enabled. Deleting intercept endpoint group: {name}")
            self.delete_intercept_endpoint_group(name=name, project=project, location=location, wait=True)
        body = {"interceptDeploymentGroup": intercept_deployment_group}
        if description:
            body["description"] = description
        if labels:
            body["labels"] = labels
        url = f"{base_url}interceptEndpointGroups?interceptEndpointGroupId={name}"
        resp = self._nsi_post(url=url, body=body)
        return self._wait_on_nsi_operation(resp) if wait else resp

    def create_intercept_endpoint_group_association(self, name, intercept_endpoint_group, network, subnetwork=None,
                                                    project=None, location="global", description=None, labels=None,
                                                    wait=True, override_existing_resources=False):
        base_url = self._network_security_base_url(project=project, location=location)
        existing = self.get_intercept_endpoint_group_association(name=name, project=project, location=location)
        if self._resource_exists(existing):
            if not override_existing_resources:
                self.logger.info(f"Intercept endpoint group association already exists: {name}")
                return existing
            self.logger.info(f"Override enabled. Deleting intercept endpoint group association: {name}")
            self.delete_intercept_endpoint_group_association(name=name, project=project, location=location, wait=True)
        body = {"interceptEndpointGroup": intercept_endpoint_group, "network": network}
        if subnetwork:
            body["subnetwork"] = subnetwork
        if description:
            body["description"] = description
        if labels:
            body["labels"] = labels
        url = f"{base_url}interceptEndpointGroupAssociations?interceptEndpointGroupAssociationId={name}"
        resp = self._nsi_post(url=url, body=body)
        return self._wait_on_nsi_operation(resp) if wait else resp

    def create_security_profile(self, name, intercept_endpoint_group, project=None, location="global",
                                description=None, labels=None, wait=True, profile_body=None,
                                override_existing_resources=False):
        base_url = self._network_security_base_url(project=project, location=location)
        url = f"{base_url}securityProfiles?securityProfileId={name}"
        existing = self.get_security_profile(name=name, project=project, location=location)
        if self._resource_exists(existing):
            if not override_existing_resources:
                self.logger.info(f"Security profile already exists: {name}")
                return existing
            self.logger.info(f"Override enabled. Deleting security profile: {name}")
            self.delete_security_profile(name=name, project=project, location=location, wait=True)
        if profile_body is None:
            profile_body = {
                "type": "INTERCEPT",
                "interceptProfile": {"interceptEndpointGroup": intercept_endpoint_group}
            }
        if description:
            profile_body["description"] = description
        if labels:
            profile_body["labels"] = labels
        resp = self._nsi_post(url=url, body=profile_body)
        return self._wait_on_nsi_operation(resp) if wait else resp

    def create_security_profile_group(self, name, security_profiles, project=None, location="global",
                                      description=None, labels=None, wait=True,
                                      override_existing_resources=False):
        base_url = self._network_security_base_url(project=project, location=location)
        existing = self.get_security_profile_group(name=name, project=project, location=location)
        if self._resource_exists(existing):
            if not override_existing_resources:
                self.logger.info(f"Security profile group already exists: {name}")
                return existing
            self.logger.info(f"Override enabled. Deleting security profile group: {name}")
            self.delete_security_profile_group(name=name, project=project, location=location, wait=True)
        body = {"securityProfiles": security_profiles}
        if description:
            body["description"] = description
        if labels:
            body["labels"] = labels
        url = f"{base_url}securityProfileGroups?securityProfileGroupId={name}"
        resp = self._nsi_post(url=url, body=body)
        return self._wait_on_nsi_operation(resp) if wait else resp

    def create_network_firewall_policy(self, policy_name, project=None, description=None, wait=True,
                                       override_existing_resources=False):
        if project is None:
            project = self.project
        existing = self.get_network_firewall_policy(policy_name=policy_name, project=project)
        if existing:
            if not override_existing_resources:
                self.logger.info(f"Network firewall policy already exists: {policy_name}")
                return existing
            self.logger.info(f"Override enabled. Deleting network firewall policy: {policy_name}")
            self.delete_network_firewall_policy(policy_name=policy_name, project=project, wait=True)
        compute_base_url = self._compute_base_url_for_project(project=project)
        url = f"{compute_base_url}global/networkFirewallPolicies"
        body = {"name": policy_name}
        if description:
            body["description"] = description
        resp = self.rest_ops.post_query(payload={"url": url, "headers": self.headers, "data": json.dumps(body)}).json()
        if 'error' in resp:
            raise Exception(resp["error"])
        if resp["status"] == "DONE":
            return resp
        if wait:
            if self.wait_on_operation(params={"operation_id": resp["id"], "project": project}):
                return resp
            self.logger.error("Network firewall policy creation failed. Exit!")
            sys.exit(1)
        return resp

    def add_network_firewall_policy_rule(self, policy_name, rule_body, project=None, priority=1000, wait=True,
                                         override_existing_resources=False):
        if project is None:
            project = self.project
        existing_rule = self.get_network_firewall_policy_rule(policy_name=policy_name, project=project,
                                                              priority=priority, rule_name=rule_body.get("name"))
        if existing_rule:
            if not override_existing_resources:
                self.logger.info(f"Firewall policy rule already exists: {policy_name}:{priority}")
                return existing_rule
            self.logger.info(f"Override enabled. Deleting firewall policy rule: {policy_name}:{priority}")
            self.delete_network_firewall_policy_rule(policy_name=policy_name, project=project, priority=priority,
                                                     wait=True)
        compute_base_url = self._compute_base_url_for_project(project=project)
        url = f"{compute_base_url}global/networkFirewallPolicies/{policy_name}/addRule?priority={priority}"
        resp = self.rest_ops.post_query(payload={"url": url, "headers": self.headers,
                                                 "data": json.dumps(rule_body)}).json()
        if 'error' in resp:
            raise Exception(resp["error"])
        if resp["status"] == "DONE":
            return resp
        if wait:
            if self.wait_on_operation(params={"operation_id": resp["id"], "project": project}):
                return resp
            self.logger.error("Network firewall policy rule add failed. Exit!")
            sys.exit(1)
        return resp

    def add_network_firewall_policy_association(self, policy_name, association_name, network, project=None, wait=True,
                                                override_existing_resources=False):
        if project is None:
            project = self.project
        existing_assoc = self.get_network_firewall_policy_association(policy_name=policy_name, project=project,
                                                                      association_name=association_name)
        if existing_assoc:
            if not override_existing_resources:
                self.logger.info(f"Firewall policy association already exists: {association_name}")
                return existing_assoc
            self.logger.info(f"Override enabled. Deleting firewall policy association: {association_name}")
            self.delete_network_firewall_policy_association(policy_name=policy_name, project=project,
                                                            association_name=association_name, wait=True)
        compute_base_url = self._compute_base_url_for_project(project=project)
        url = f"{compute_base_url}global/networkFirewallPolicies/{policy_name}/addAssociation"
        body = {"name": association_name, "attachmentTarget": network}
        resp = self.rest_ops.post_query(payload={"url": url, "headers": self.headers, "data": json.dumps(body)}).json()
        if 'error' in resp:
            raise Exception(resp["error"])
        if resp["status"] == "DONE":
            return resp
        if wait:
            if self.wait_on_operation(params={"operation_id": resp["id"], "project": project}):
                return resp
            self.logger.error("Network firewall policy association failed. Exit!")
            sys.exit(1)
        return resp

    def create_vpc_firewall_rule(self, rule_body, project=None, wait=True, override_existing_resources=False):
        if project is None:
            project = self.project
        rule_name = rule_body.get("name", None)
        if rule_name:
            existing_rule = self.get_vpc_firewall_rule(rule_name=rule_name, project=project)
            if existing_rule:
                if not override_existing_resources:
                    self.logger.info(f"Firewall rule already exists: {rule_name}")
                    return existing_rule
                self.logger.info(f"Override enabled. Deleting firewall rule: {rule_name}")
                self.delete_vpc_firewall_rule(rule_name=rule_name, project=project, wait=True)
        compute_base_url = self._compute_base_url_for_project(project=project)
        url = f"{compute_base_url}global/firewalls"
        resp = self.rest_ops.post_query(payload={"url": url, "headers": self.headers,
                                                 "data": json.dumps(rule_body)}).json()
        if 'error' in resp:
            raise Exception(resp["error"])
        if resp["status"] == "DONE":
            return resp
        if wait:
            if self.wait_on_operation(params={"operation_id": resp["id"], "project": project}):
                return resp
            self.logger.error("Firewall rule creation failed. Exit!")
            sys.exit(1)
        return resp

    def get_security_profile(self, name, project=None, location="global"):
        base_url = self._network_security_base_url(project=project, location=location)
        return self._nsi_get(f"{base_url}securityProfiles/{name}")

    def list_security_profiles(self, project=None, location="global"):
        base_url = self._network_security_base_url(project=project, location=location)
        return self._nsi_list(base_url=base_url, resource_path="securityProfiles", items_key="securityProfiles")

    def get_security_profile_group(self, name, project=None, location="global"):
        base_url = self._network_security_base_url(project=project, location=location)
        return self._nsi_get(f"{base_url}securityProfileGroups/{name}")

    def list_security_profile_groups(self, project=None, location="global"):
        base_url = self._network_security_base_url(project=project, location=location)
        return self._nsi_list(base_url=base_url, resource_path="securityProfileGroups",
                              items_key="securityProfileGroups")

    def delete_intercept_endpoint_group(self, name, project=None, location="global", wait=True):
        base_url = self._network_security_base_url(project=project, location=location)
        resp = self._nsi_delete(f"{base_url}interceptEndpointGroups/{name}")
        return self._wait_on_nsi_operation(resp) if wait else resp

    def delete_intercept_endpoint_group_association(self, name, project=None, location="global", wait=True):
        base_url = self._network_security_base_url(project=project, location=location)
        resp = self._nsi_delete(f"{base_url}interceptEndpointGroupAssociations/{name}")
        return self._wait_on_nsi_operation(resp) if wait else resp

    def delete_security_profile(self, name, project=None, location="global", wait=True):
        base_url = self._network_security_base_url(project=project, location=location)
        resp = self._nsi_delete(f"{base_url}securityProfiles/{name}")
        return self._wait_on_nsi_operation(resp) if wait else resp

    def delete_security_profile_group(self, name, project=None, location="global", wait=True):
        base_url = self._network_security_base_url(project=project, location=location)
        resp = self._nsi_delete(f"{base_url}securityProfileGroups/{name}")
        return self._wait_on_nsi_operation(resp) if wait else resp

    def update_intercept_endpoint_group(self, name, intercept_deployment_group, project=None, location="global",
                                        description=None, labels=None, wait=True):
        self.delete_intercept_endpoint_group(name=name, project=project, location=location, wait=True)
        return self.create_intercept_endpoint_group(
            name=name,
            intercept_deployment_group=intercept_deployment_group,
            project=project,
            location=location,
            description=description,
            labels=labels,
            wait=wait,
            override_existing_resources=False
        )

    def update_intercept_endpoint_group_association(self, name, intercept_endpoint_group, network, subnetwork=None,
                                                    project=None, location="global", description=None, labels=None,
                                                    wait=True):
        self.delete_intercept_endpoint_group_association(name=name, project=project, location=location, wait=True)
        return self.create_intercept_endpoint_group_association(
            name=name,
            intercept_endpoint_group=intercept_endpoint_group,
            network=network,
            subnetwork=subnetwork,
            project=project,
            location=location,
            description=description,
            labels=labels,
            wait=wait,
            override_existing_resources=False
        )

    def update_security_profile(self, name, intercept_endpoint_group, project=None, location="global",
                                description=None, labels=None, wait=True, profile_body=None):
        self.delete_security_profile(name=name, project=project, location=location, wait=True)
        return self.create_security_profile(
            name=name,
            intercept_endpoint_group=intercept_endpoint_group,
            project=project,
            location=location,
            description=description,
            labels=labels,
            wait=wait,
            profile_body=profile_body,
            override_existing_resources=False
        )

    def update_security_profile_group(self, name, security_profiles, project=None, location="global",
                                      description=None, labels=None, wait=True):
        self.delete_security_profile_group(name=name, project=project, location=location, wait=True)
        return self.create_security_profile_group(
            name=name,
            security_profiles=security_profiles,
            project=project,
            location=location,
            description=description,
            labels=labels,
            wait=wait,
            override_existing_resources=False
        )

    def list_network_firewall_policies(self, project=None):
        if project is None:
            project = self.project
        policies = []
        req = self.compute_client.networkFirewallPolicies().list(project=project)
        while req is not None:
            resp = req.execute()
            policies.extend(resp.get("items", []))
            req = self.compute_client.networkFirewallPolicies().list_next(previous_request=req, previous_response=resp)
        return policies

    def get_network_firewall_policy(self, policy_name, project=None):
        if project is None:
            project = self.project
        policies = self.list_network_firewall_policies(project=project)
        for policy in policies:
            if policy.get("name") == policy_name:
                return policy
        return None

    def delete_network_firewall_policy(self, policy_name, project=None, wait=True):
        if project is None:
            project = self.project
        compute_base_url = self._compute_base_url_for_project(project=project)
        url = f"{compute_base_url}global/networkFirewallPolicies/{policy_name}"
        resp = self.rest_ops.delete_query(payload={"url": url, "headers": self.headers})
        resp_json = resp.json() if resp is not None and hasattr(resp, "json") else {}
        if wait and resp_json and resp_json.get("status") != "DONE":
            if self.wait_on_operation(params={"operation_id": resp_json["id"], "project": project}):
                return resp_json
            self.logger.error("Network firewall policy delete failed. Exit!")
            sys.exit(1)
        return resp_json

    def list_network_firewall_policy_rules(self, policy_name, project=None):
        if project is None:
            project = self.project
        compute_base_url = self._compute_base_url_for_project(project=project)
        url = f"{compute_base_url}global/networkFirewallPolicies/{policy_name}/listRules"
        resp = self.rest_ops.get_query(payload={"url": url, "headers": self.headers})
        return resp.get("rules", []) if isinstance(resp, dict) else []

    def get_network_firewall_policy_rule(self, policy_name, project=None, priority=None, rule_name=None):
        rules = self.list_network_firewall_policy_rules(policy_name=policy_name, project=project)
        for rule in rules:
            if priority is not None and rule.get("priority") == priority:
                return rule
            if rule_name and rule.get("rule", {}).get("name") == rule_name:
                return rule
        return None

    def delete_network_firewall_policy_rule(self, policy_name, project=None, priority=None, wait=True):
        if project is None:
            project = self.project
        if priority is None:
            self.logger.error("priority must be provided to delete a firewall policy rule")
            sys.exit(1)
        compute_base_url = self._compute_base_url_for_project(project=project)
        url = f"{compute_base_url}global/networkFirewallPolicies/{policy_name}/removeRule?priority={priority}"
        resp = self.rest_ops.post_query(payload={"url": url, "headers": self.headers,
                                                 "data": json.dumps({})}).json()
        if wait and resp.get("status") != "DONE":
            if self.wait_on_operation(params={"operation_id": resp["id"], "project": project}):
                return resp
            self.logger.error("Network firewall policy rule delete failed. Exit!")
            sys.exit(1)
        return resp

    def list_network_firewall_policy_associations(self, policy_name, project=None):
        policy = self.get_network_firewall_policy(policy_name=policy_name, project=project)
        return policy.get("associations", []) if policy else []

    def get_network_firewall_policy_association(self, policy_name, project=None, association_name=None):
        associations = self.list_network_firewall_policy_associations(policy_name=policy_name, project=project)
        for assoc in associations:
            if assoc.get("name") == association_name:
                return assoc
        return None

    def delete_network_firewall_policy_association(self, policy_name, project=None, association_name=None, wait=True):
        if project is None:
            project = self.project
        if association_name is None:
            self.logger.error("association_name must be provided to delete a firewall policy association")
            sys.exit(1)
        compute_base_url = self._compute_base_url_for_project(project=project)
        url = f"{compute_base_url}global/networkFirewallPolicies/{policy_name}/removeAssociation"
        body = {"name": association_name}
        resp = self.rest_ops.post_query(payload={"url": url, "headers": self.headers,
                                                 "data": json.dumps(body)}).json()
        if wait and resp.get("status") != "DONE":
            if self.wait_on_operation(params={"operation_id": resp["id"], "project": project}):
                return resp
            self.logger.error("Network firewall policy association delete failed. Exit!")
            sys.exit(1)
        return resp

    def list_vpc_firewall_rules(self, project=None):
        if project is None:
            project = self.project
        rules = []
        req = self.compute_client.firewalls().list(project=project)
        while req is not None:
            resp = req.execute()
            rules.extend(resp.get("items", []))
            req = self.compute_client.firewalls().list_next(previous_request=req, previous_response=resp)
        return rules

    def get_vpc_firewall_rule(self, rule_name, project=None):
        rules = self.list_vpc_firewall_rules(project=project)
        for rule in rules:
            if rule.get("name") == rule_name:
                return rule
        return None

    def delete_vpc_firewall_rule(self, rule_name, project=None, wait=True):
        if project is None:
            project = self.project
        compute_base_url = self._compute_base_url_for_project(project=project)
        url = f"{compute_base_url}global/firewalls/{rule_name}"
        resp = self.rest_ops.delete_query(payload={"url": url, "headers": self.headers})
        resp_json = resp.json() if resp is not None and hasattr(resp, "json") else {}
        if wait and resp_json and resp_json.get("status") != "DONE":
            if self.wait_on_operation(params={"operation_id": resp_json["id"], "project": project}):
                return resp_json
            self.logger.error("Firewall rule delete failed. Exit!")
            sys.exit(1)
        return resp_json

    def get_instance_by_name(self, zone, instance_name, project=None):
        if project is None:
            project = self.project
        try:
            request = self.compute_client.instances().get(project=project, zone=zone, instance=instance_name)
            return request.execute()
        except Exception:
            return None

    def delete_instance(self, zone, instance_name, project=None, wait=True):
        if project is None:
            project = self.project
        compute_base_url = self._compute_base_url_for_project(project=project)
        url = f"{compute_base_url}zones/{zone}/instances/{instance_name}"
        resp = self.rest_ops.delete_query(payload={"url": url, "headers": self.headers})
        resp_json = resp.json() if resp is not None and hasattr(resp, "json") else {}
        if wait and resp_json and resp_json.get("status") != "DONE":
            if self.wait_on_operation(params={"operation_id": resp_json["id"], "zone": zone, "project": project},
                                      operation_type="zonal"):
                return resp_json
            self.logger.error("Instance delete failed. Exit!")
            sys.exit(1)
        return resp_json

    def update_vpc(self, vpc_name, project=None, routing_mode="REGIONAL", auto_create_subnetworks=False,
                   description=None, wait=True):
        self.delete_vpc(vpc_name=vpc_name, wait=True, project=project)
        return self.create_vpc(vpc_name=vpc_name, project=project, routing_mode=routing_mode,
                               auto_create_subnetworks=auto_create_subnetworks, description=description, wait=wait,
                               override_existing_resources=False)

    def update_subnet(self, subnet_name, region, ip_cidr_range, vpc_name=None, network=None, project=None,
                      enable_flow_logs=False, private_ip_google_access=True, secondary_ip_ranges=None, wait=True):
        self.delete_subnet(subnet_config={"name": subnet_name, "region": region}, wait=True, project=project)
        return self.create_subnet(subnet_name=subnet_name, region=region, ip_cidr_range=ip_cidr_range,
                                  vpc_name=vpc_name, network=network, project=project,
                                  enable_flow_logs=enable_flow_logs,
                                  private_ip_google_access=private_ip_google_access,
                                  secondary_ip_ranges=secondary_ip_ranges, wait=wait,
                                  override_existing_resources=False)

    def update_network_firewall_policy(self, policy_name, project=None, description=None, wait=True):
        self.delete_network_firewall_policy(policy_name=policy_name, project=project, wait=True)
        return self.create_network_firewall_policy(policy_name=policy_name, project=project,
                                                   description=description, wait=wait,
                                                   override_existing_resources=False)

    def update_network_firewall_policy_rule(self, policy_name, rule_body, project=None, priority=1000, wait=True):
        self.delete_network_firewall_policy_rule(policy_name=policy_name, project=project,
                                                 priority=priority, wait=True)
        return self.add_network_firewall_policy_rule(policy_name=policy_name, rule_body=rule_body, project=project,
                                                     priority=priority, wait=wait,
                                                     override_existing_resources=False)

    def update_network_firewall_policy_association(self, policy_name, association_name, network,
                                                    project=None, wait=True):
        self.delete_network_firewall_policy_association(policy_name=policy_name, project=project,
                                                        association_name=association_name, wait=True)
        return self.add_network_firewall_policy_association(policy_name=policy_name,
                                                            association_name=association_name,
                                                            network=network,
                                                            project=project, wait=wait,
                                                            override_existing_resources=False)

    def update_vpc_firewall_rule(self, rule_body, project=None, wait=True):
        rule_name = rule_body.get("name", None)
        if rule_name:
            self.delete_vpc_firewall_rule(rule_name=rule_name, project=project, wait=True)
        return self.create_vpc_firewall_rule(rule_body=rule_body, project=project, wait=wait,
                                             override_existing_resources=False)

    def list_instances_by_filter(self, project=None, zone=None, instance_filter=None):
        if project is None:
            project = self.project
        instances = []
        if zone:
            req = self.compute_client.instances().list(project=project, zone=zone, filter=instance_filter)
            while req is not None:
                resp = req.execute()
                instances.extend(resp.get("items", []))
                req = self.compute_client.instances().list_next(previous_request=req, previous_response=resp)
        else:
            req = self.compute_client.instances().aggregatedList(project=project, filter=instance_filter)
            while req is not None:
                resp = req.execute()
                for zone_items in resp.get("items", {}).values():
                    instances.extend(zone_items.get("instances", []))
                req = self.compute_client.instances().aggregatedList_next(previous_request=req,
                                                                           previous_response=resp)
        return instances

    def update_instance_labels(self, zone, instance_name, labels, project=None):
        if project is None:
            project = self.project
        instance = self.get_instance_by_name(zone=zone, instance_name=instance_name, project=project)
        if instance is None:
            self.logger.error(f"Instance not found: {instance_name} in zone: {zone}")
            sys.exit(1)
        label_fingerprint = instance.get("labelFingerprint")
        body = {"labels": labels, "labelFingerprint": label_fingerprint}
        req = self.compute_client.instances().setLabels(project=project, zone=zone,
                                                        instance=instance_name, body=body)
        return req.execute()

    def get_instance_private_ip(self, zone, instance_name, project=None):
        if project is None:
            project = self.project
        request = self.compute_client.instances().get(project=project, zone=zone, instance=instance_name)
        response = request.execute()
        if response.get("networkInterfaces"):
            return response["networkInterfaces"][0]["networkIP"]
        return None

    def get_serial_port_output(self, zone, instance_name, project=None, port=1, start=0):
        if project is None:
            project = self.project
        request = self.compute_client.instances().getSerialPortOutput(project=project, zone=zone,
                                                                       instance=instance_name, port=port, start=start)
        return request.execute()

    def create_nsi_test_instances(self, project, vpc_name, subnet_name, region, server_zone, client_zone,
                                  server_name, client_name, instance_type, image_name, image_project, tags,
                                  ssh_key, server_port=8080, wait_for_server=True,
                                  override_existing_resources=False):
        subnet_self_link = self._build_subnet_self_link(subnet_name=subnet_name, region=region, project=project)
        image_url = self.get_image(image_name=image_name, image_project=image_project)["selfLink"]
        if override_existing_resources:
            existing_server = self.get_instance_by_name(zone=server_zone, instance_name=server_name, project=project)
            if existing_server:
                self.logger.info(f"Override enabled. Deleting server instance: {server_name}")
                self.delete_instance(zone=server_zone, instance_name=server_name, project=project, wait=True)
            existing_client = self.get_instance_by_name(zone=client_zone, instance_name=client_name, project=project)
            if existing_client:
                self.logger.info(f"Override enabled. Deleting client instance: {client_name}")
                self.delete_instance(zone=client_zone, instance_name=client_name, project=project, wait=True)
        server_script = "\n".join([
            "#!/bin/bash",
            "set -e",
            "sudo apt-get update -y",
            "sudo apt-get install -y python3",
            f"nohup python3 -m http.server {server_port} >/var/log/nsi_http.log 2>&1 &",
            f'echo "NSI_SERVER_READY port={server_port}" | tee /dev/serial0'
        ])
        server_kwargs = {
            "instance_name": server_name,
            "instance_type": instance_type,
            "install_script": server_script,
            "ssh_key": ssh_key,
            "tags": tags,
            "zone": server_zone,
            "image_url": image_url,
            "subnet": subnet_self_link,
            "label_dict": {"role": "nsi-server"},
            "is_spot_enabled": False
        }
        self.deploy_instances(kwargs_dict_list=[server_kwargs])
        if wait_for_server:
            time.sleep(20)
        server_ip = self.get_instance_private_ip(zone=server_zone, instance_name=server_name, project=project)
        if server_ip is None:
            self.logger.error("Failed to determine server private IP. Exit!")
            sys.exit(1)
        client_script = "\n".join([
            "#!/bin/bash",
            "set -e",
            f"TARGET_IP={server_ip}",
            f"TARGET_PORT={server_port}",
            "for i in $(seq 1 20); do",
            "  if curl -s --max-time 5 http://${TARGET_IP}:${TARGET_PORT}/ >/tmp/nsi_client.out; then",
            '    echo "NSI_CLIENT_SUCCESS ${TARGET_IP}:${TARGET_PORT}" | tee /dev/serial0',
            "    exit 0",
            "  fi",
            "  sleep 5",
            "done",
            'echo "NSI_CLIENT_FAILED ${TARGET_IP}:${TARGET_PORT}" | tee /dev/serial0',
            "exit 1"
        ])
        client_kwargs = {
            "instance_name": client_name,
            "instance_type": instance_type,
            "install_script": client_script,
            "ssh_key": ssh_key,
            "tags": tags,
            "zone": client_zone,
            "image_url": image_url,
            "subnet": subnet_self_link,
            "label_dict": {"role": "nsi-client"},
            "is_spot_enabled": False
        }
        self.deploy_instances(kwargs_dict_list=[client_kwargs])
        return {"server_ip": server_ip, "server_name": server_name, "client_name": client_name}

    def verify_nsi_inband_inspection(self, consumer_project, client_zone, client_instance_name,
                                     intercept_endpoint_group_association, location="global"):
        assoc = self.get_intercept_endpoint_group_association(
            name=intercept_endpoint_group_association, project=consumer_project, location=location)
        if isinstance(assoc, dict):
            self.logger.info(f"Intercept endpoint group association state: {assoc.get('state', 'UNKNOWN')}")
        serial_output = self.get_serial_port_output(project=consumer_project, zone=client_zone,
                                                     instance_name=client_instance_name)
        output_text = serial_output.get("contents", "")
        if "NSI_CLIENT_SUCCESS" in output_text:
            self.logger.info("Client connectivity test succeeded (NSI_CLIENT_SUCCESS in serial output).")
            return True
        self.logger.warning("Client connectivity test did not report success in serial output.")
        return False

    def infra_setup(self, producer_cfg=None, consumer_cfg=None, nsi_cfg=None, vm_cfg=None,
                    override_existing_resources=None, use_config=True):
        if override_existing_resources is None:
            override_existing_resources = False
        if use_config and (producer_cfg is None or consumer_cfg is None or nsi_cfg is None or vm_cfg is None):
            cfg = self._load_nsi_inband_config()
            if cfg:
                producer_cfg = producer_cfg or cfg.get("producer_cfg")
                consumer_cfg = consumer_cfg or cfg.get("consumer_cfg")
                nsi_cfg = nsi_cfg or cfg.get("nsi_cfg")
                vm_cfg = vm_cfg or cfg.get("vm_cfg")
                if override_existing_resources is False:
                    override_existing_resources = cfg.get("override_existing_resources", False)
        return self.deploy_nsi_inband_consumer_resources(
            producer_cfg=producer_cfg,
            consumer_cfg=consumer_cfg,
            nsi_cfg=nsi_cfg,
            vm_cfg=vm_cfg,
            override_existing_resources=override_existing_resources,
            use_config=False
        )

    def infra_cleanup(self, consumer_cfg=None, nsi_cfg=None, vm_cfg=None,
                      delete_vpcs_on_cleanup=None, use_config=True):
        if use_config and (consumer_cfg is None or nsi_cfg is None or vm_cfg is None or
                           delete_vpcs_on_cleanup is None):
            cfg = self._load_nsi_inband_config()
            if cfg:
                consumer_cfg = consumer_cfg or cfg.get("consumer_cfg")
                nsi_cfg = nsi_cfg or cfg.get("nsi_cfg")
                vm_cfg = vm_cfg or cfg.get("vm_cfg")
                if delete_vpcs_on_cleanup is None:
                    delete_vpcs_on_cleanup = cfg.get("delete_vpcs_on_cleanup", False)
        if any(x is None for x in [consumer_cfg, nsi_cfg, vm_cfg]):
            self.logger.error("Missing required configs for NSI in-band cleanup. Provide params or config section.")
            sys.exit(1)
        consumer_project = consumer_cfg.get("project", self.project)
        location = nsi_cfg.get("location", "global")
        vpc_name = consumer_cfg["vpc_name"]

        # Delete test VMs
        server_name = vm_cfg.get("server_name")
        client_name = vm_cfg.get("client_name")
        if server_name:
            self.delete_instance(zone=vm_cfg["server_zone"], instance_name=server_name,
                                 project=consumer_project, wait=True)
        if client_name:
            self.delete_instance(zone=vm_cfg["client_zone"], instance_name=client_name,
                                 project=consumer_project, wait=True)

        # Delete VPC firewall allow rule
        allow_rule_name = f"{vpc_name}-allow-internal"
        if self.get_vpc_firewall_rule(rule_name=allow_rule_name, project=consumer_project):
            self.delete_vpc_firewall_rule(rule_name=allow_rule_name, project=consumer_project, wait=True)

        # Delete firewall policy association, rule, and policy
        policy_name = nsi_cfg["firewall_policy"]
        assoc_name = nsi_cfg["firewall_policy_association"]
        rule_priority = nsi_cfg.get("firewall_policy_rule_priority", 1000)
        if self.get_network_firewall_policy_association(policy_name=policy_name, project=consumer_project,
                                                        association_name=assoc_name):
            self.delete_network_firewall_policy_association(policy_name=policy_name, project=consumer_project,
                                                            association_name=assoc_name, wait=True)
        if self.get_network_firewall_policy_rule(policy_name=policy_name, project=consumer_project,
                                                 priority=rule_priority):
            self.delete_network_firewall_policy_rule(policy_name=policy_name, project=consumer_project,
                                                     priority=rule_priority, wait=True)
        if self.get_network_firewall_policy(policy_name=policy_name, project=consumer_project):
            self.delete_network_firewall_policy(policy_name=policy_name, project=consumer_project, wait=True)

        # Delete security profile group and profile
        spg_name = nsi_cfg["security_profile_group"]
        sp_name = nsi_cfg["security_profile"]
        if self.get_security_profile_group(name=spg_name, project=consumer_project, location=location):
            self.delete_security_profile_group(name=spg_name, project=consumer_project, location=location, wait=True)
        if self.get_security_profile(name=sp_name, project=consumer_project, location=location):
            self.delete_security_profile(name=sp_name, project=consumer_project, location=location, wait=True)

        # Delete intercept endpoint group association and group
        iega_name = nsi_cfg["intercept_endpoint_group_association"]
        ieg_name = nsi_cfg["intercept_endpoint_group"]
        if self.get_intercept_endpoint_group_association(name=iega_name, project=consumer_project, location=location):
            self.delete_intercept_endpoint_group_association(name=iega_name, project=consumer_project,
                                                             location=location, wait=True)
        if self.get_intercept_endpoint_group(name=ieg_name, project=consumer_project, location=location):
            self.delete_intercept_endpoint_group(name=ieg_name, project=consumer_project, location=location, wait=True)

        # Delete subnets and VPC (optional)
        if delete_vpcs_on_cleanup:
            subnets = consumer_cfg.get("subnets", [])
            for subnet in subnets:
                self.delete_subnet(subnet_config={"name": subnet["name"], "region": subnet["region"]},
                                   wait=True, project=consumer_project)
            self.delete_vpc(vpc_name=vpc_name, wait=True, project=consumer_project)
        self.logger.info("NSI in-band infrastructure cleanup completed.")
        return True

    def deploy_nsi_inband_consumer_resources(self, producer_cfg=None, consumer_cfg=None, nsi_cfg=None, vm_cfg=None,
                                             override_existing_resources=False, use_config=True):
        """
        Deploy in-band NSI consumer resources and verify workflow.
        producer_cfg: {project, location, intercept_deployment_group}
        consumer_cfg: {project, vpc_name, subnets: [{name, region, ip_cidr_range}], description}
        nsi_cfg: {location, intercept_endpoint_group, intercept_endpoint_group_association, security_profile,
                  security_profile_group, firewall_policy, firewall_policy_rule_priority, firewall_policy_association,
                  match: {src_ip_ranges, dest_ip_ranges, layer4_configs}}
        vm_cfg: {subnet_name, region, server_zone, client_zone, server_name, client_name, instance_type,
                 image_name, image_project, tags, ssh_key, server_port}
        """
        if use_config and (producer_cfg is None or consumer_cfg is None or nsi_cfg is None or vm_cfg is None):
            cfg = self._load_nsi_inband_config()
            if cfg:
                producer_cfg = producer_cfg or cfg.get("producer_cfg")
                consumer_cfg = consumer_cfg or cfg.get("consumer_cfg")
                nsi_cfg = nsi_cfg or cfg.get("nsi_cfg")
                vm_cfg = vm_cfg or cfg.get("vm_cfg")
                if not override_existing_resources:
                    override_existing_resources = cfg.get("override_existing_resources", False)
        if any(x is None for x in [producer_cfg, consumer_cfg, nsi_cfg, vm_cfg]):
            self.logger.error("Missing required configs for NSI in-band deployment. Provide params or config section.")
            sys.exit(1)
        producer_project = producer_cfg.get("project", self.project)
        consumer_project = consumer_cfg.get("project", self.project)
        location = nsi_cfg.get("location", "global")
        vpc_name = consumer_cfg["vpc_name"]
        subnets = consumer_cfg.get("subnets", [])

        self.create_vpc(vpc_name=vpc_name, project=consumer_project,
                        description=consumer_cfg.get("description", None),
                        override_existing_resources=override_existing_resources)
        subnet_configs = []
        for subnet in subnets:
            subnet_configs.append({
                "name": subnet["name"],
                "region": subnet["region"],
                "ip_cidr_range": subnet["ip_cidr_range"],
                "vpc_name": vpc_name,
                "project": consumer_project
            })
        if subnet_configs:
            self.create_subnets(subnet_configs=subnet_configs,
                                override_existing_resources=override_existing_resources)

        producer_idg = producer_cfg["intercept_deployment_group"]
        if not producer_idg.startswith("projects/"):
            producer_idg = (f"projects/{producer_project}/locations/{location}/"
                            f"interceptDeploymentGroups/{producer_idg}")
        producer_idg_resp = self.get_intercept_deployment_group(name=producer_idg.split("/")[-1],
                                                                project=producer_project, location=location)
        if self._is_resource_not_found(producer_idg_resp):
            self.logger.error("Producer intercept deployment group not found. Exit!")
            sys.exit(1)

        self.create_intercept_endpoint_group(
            name=nsi_cfg["intercept_endpoint_group"],
            intercept_deployment_group=producer_idg,
            project=consumer_project,
            location=location,
            override_existing_resources=override_existing_resources
        )

        consumer_network = self._build_network_self_link(vpc_name=vpc_name, project=consumer_project)
        subnet_self_link = self._build_subnet_self_link(subnet_name=vm_cfg["subnet_name"],
                                                        region=vm_cfg["region"], project=consumer_project)
        enforce_order = nsi_cfg.get("enforce_policy_order", True)
        desired_order = nsi_cfg.get("policy_order", "BEFORE_CLASSIC_FIREWALL")
        self.ensure_network_firewall_policy_order(vpc_name=vpc_name, project=consumer_project,
                                                  desired_order=desired_order, auto_fix=enforce_order, wait=True)
        intercept_endpoint_group_full = (f"projects/{consumer_project}/locations/{location}/"
                                         f"interceptEndpointGroups/{nsi_cfg['intercept_endpoint_group']}")
        self.create_intercept_endpoint_group_association(
            name=nsi_cfg["intercept_endpoint_group_association"],
            intercept_endpoint_group=intercept_endpoint_group_full,
            network=consumer_network,
            subnetwork=subnet_self_link,
            project=consumer_project,
            location=location,
            override_existing_resources=override_existing_resources
        )

        security_profile_name = nsi_cfg["security_profile"]
        security_profile_group_name = nsi_cfg["security_profile_group"]
        security_profile_full = (f"projects/{consumer_project}/locations/{location}/"
                                 f"securityProfiles/{security_profile_name}")
        security_profile_group_full = (f"projects/{consumer_project}/locations/{location}/"
                                       f"securityProfileGroups/{security_profile_group_name}")
        self.create_security_profile(
            name=security_profile_name,
            intercept_endpoint_group=intercept_endpoint_group_full,
            project=consumer_project,
            location=location,
            override_existing_resources=override_existing_resources
        )
        self.create_security_profile_group(
            name=security_profile_group_name,
            security_profiles=[security_profile_full],
            project=consumer_project,
            location=location,
            override_existing_resources=override_existing_resources
        )

        firewall_policy_name = nsi_cfg["firewall_policy"]
        self.create_network_firewall_policy(policy_name=firewall_policy_name, project=consumer_project,
                                            description="NSI in-band firewall policy",
                                            override_existing_resources=override_existing_resources)
        match_cfg = nsi_cfg.get("match", {})
        if not match_cfg:
            if subnets:
                subnet_cidr = subnets[0]["ip_cidr_range"]
                match_cfg = {
                    "srcIpRanges": [subnet_cidr],
                    "destIpRanges": [subnet_cidr],
                    "layer4Configs": [{"ipProtocol": "all"}]
                }
            else:
                match_cfg = {
                    "srcIpRanges": ["0.0.0.0/0"],
                    "destIpRanges": ["0.0.0.0/0"],
                    "layer4Configs": [{"ipProtocol": "all"}]
                }
        rule_body = {
            "action": "applySecurityProfileGroup",
            "securityProfileGroup": security_profile_group_full,
            "direction": nsi_cfg.get("firewall_policy_rule_direction", "INGRESS"),
            "match": match_cfg,
            "description": "NSI in-band interception rule"
        }
        priority = nsi_cfg.get("firewall_policy_rule_priority", 1000)
        self.add_network_firewall_policy_rule(policy_name=firewall_policy_name, rule_body=rule_body,
                                              project=consumer_project, priority=priority,
                                              override_existing_resources=override_existing_resources)
        self.add_network_firewall_policy_association(
            policy_name=firewall_policy_name,
            association_name=nsi_cfg["firewall_policy_association"],
            network=consumer_network,
            project=consumer_project,
            override_existing_resources=override_existing_resources
        )

        allow_rule = {
            "name": f"{vpc_name}-allow-internal",
            "direction": "INGRESS",
            "priority": 1000,
            "network": consumer_network,
            "allowed": [{"IPProtocol": "all"}],
            "sourceRanges": [subnets[0]["ip_cidr_range"]] if subnets else ["0.0.0.0/0"],
            "targetTags": vm_cfg.get("tags", [])
        }
        self.create_vpc_firewall_rule(rule_body=allow_rule, project=consumer_project,
                                      override_existing_resources=override_existing_resources)

        self.create_nsi_test_instances(
            project=consumer_project,
            vpc_name=vpc_name,
            subnet_name=vm_cfg["subnet_name"],
            region=vm_cfg["region"],
            server_zone=vm_cfg["server_zone"],
            client_zone=vm_cfg["client_zone"],
            server_name=vm_cfg["server_name"],
            client_name=vm_cfg["client_name"],
            instance_type=vm_cfg["instance_type"],
            image_name=vm_cfg["image_name"],
            image_project=vm_cfg["image_project"],
            tags=vm_cfg["tags"],
            ssh_key=vm_cfg["ssh_key"],
            server_port=vm_cfg.get("server_port", 8080),
            override_existing_resources=override_existing_resources
        )

        return self.verify_nsi_inband_inspection(
            consumer_project=consumer_project,
            client_zone=vm_cfg["client_zone"],
            client_instance_name=vm_cfg["client_name"],
            intercept_endpoint_group_association=nsi_cfg["intercept_endpoint_group_association"],
            location=location
        )

    @access_token_validator
    def get_all_vpc_subnets(self, query_filter=None, ret_obj=True):
        """
        Get all VPC-subnets in the project (matching filter if provided)
        :param query_filter: None (default) or an expression in string format: "name=vamsi-vpc*"
        :param ret_obj: bool: True (default), if False, returns as the resp object as it is
        :return: dict object containing VPCs with vpc name as key. Subnets can be fetched individually as shown below:
                # subnet = vpcs[0]["subnetworks"][0]
                # resp = subnet.get_object().execute <-- example on how to call each individual object
        """
        request = self.compute_client.networks().list(project=self.project, filter=query_filter)
        payload = dict()
        payload["headers"] = self.headers
        payload["params"] = None
        vpcs = dict()
        while request is not None:
            response = request.execute()
            if response.get("items", None) is None:
                self.logger.error("No response found")
                break
            for network in response['items']:
                if ret_obj:
                    subnetworks = []
                    if "subnetworks" not in network:
                        self.logger.info(f"Skipping an empty VPC: {network['name']}")
                        continue
                    for subnet in network["subnetworks"]:
                        payload["url"] = subnet
                        subnet_resp = GetObject(payload=payload, rest_ops=self.rest_ops, ret_json_obj=True)
                        subnetworks.append(subnet_resp)
                    network["subnetworks"] = subnetworks
                vpcs[network["name"]] = network
            request = self.compute_client.networks().list_next(previous_request=request, previous_response=response)
        return vpcs

    def get_subnets(self, region, query_filter, project=None, vpc_name=None) -> list:
        """
        get subnets that match the filter
        :param region: "us-east1"
        :param query_filter: "ipCidrRange eq 10.67.1.0/24"; or: (ipCidrRange = "10.67.1.0/24") AND
        (network = "https://www.googleapis.com/compute/v1/projects/zs-167220/global/networks/gcp-fnet-spoke1-0")
        :param project: "zs-167220"
        :param vpc_name: https://www.googleapis.com/compute/v1/projects/zs-167220/global/networks/gcp-fn-spoke1-0
        :return:
        """
        self.logger.info(f"Get Subnetworks from Project: {project} in region: {region}")
        if project is None:
            project = self.project
        if vpc_name:
            if ("AND" not in query_filter or "OR" not in query_filter) and not query_filter.startswith("(") and \
                    "eq" in query_filter:
                query_filter = query_filter.split("eq")
                if not query_filter[-1].startswith('"'):
                    query_filter[-1] = f'"{query_filter[-1]}"'
                query_filter = " = ".join(query_filter)
                query_filter = f"({query_filter})"
            query_filter += f" AND ({self.compute_base_url + 'global/networks/' + vpc_name})"
        subnetworks = list()
        self.logger.info(f"Using query filter: {query_filter}")
        try:
            request = self.compute_client.subnetworks().list(project=project, region=region, filter=query_filter)
            while request is not None:
                response = request.execute()
                if response.get("error", None) is not None:
                    self.logger.error(f"Got error while trying to fetch the subnetworks: \nError: {response['error']}")
                    sys.exit(1)
                if response.get("items", None) is None:
                    self.logger.error(f"No response found. Verify the subnet query filter: {query_filter}")
                    break
                self.logger.info(f"Request executed: \nRequest kind: {response.kind}. \nRequest id: {response.id}")
                subnetworks.extend(response['items'])
                request = self.compute_client.subnetworks().list_next(previous_request=request,
                                                                      previous_response=response)
        except Exception as e:
            self.logger.error(f"Exception while trying to collect all subnetworks associated with this filter: "
                              f"{query_filter}: {e}")
            sys.exit(1)
        else:
            return subnetworks

    def create_vpc_subnets(self, launch_config=None):
        """
        Creates VPC and Subnets as per the launch_config( if provided) or GCP-EC2.LAUNCH section in the config file
        :param launch_config: a list of dictionaries to create VPC and respective subnets
                             {"set-1": {key-value pairs of all params needed}
        :return:
        """
        common_vpc_config = {"routingConfig": {"routingMode": "REGIONAL"}, "autoCreateSubnetworks": False}
        common_subnet_config = {"enableFlowLogs": False, "privateIpGoogleAccess": True, "secondaryIpRanges": []}
        available_vpc_subnets = self.get_all_vpc_subnets()
        available_vpcs = set(available_vpc_subnets.keys())
        self.logger.info(f"Existing VPCs:{available_vpcs}")
        if launch_config is None:
            launch_config = self.config["GCP-EC2"]["LAUNCH"]
        for config_set in launch_config:
            if launch_config[config_set] != {} and launch_config[config_set].as_bool('ENABLE') is True:
                config = launch_config[config_set]
                cfg_vpc_names = config.as_list("VPCS")  # list of VPCS or vpc-name regex
                if "VPC_PEERING" in config:
                    vpc_peering = config.as_list("VPC_PEERING")
                else:
                    vpc_peering = None
                # check if all the vpcs provided do exist already
                if set(cfg_vpc_names).issubset(available_vpcs):
                    self.logger.info(f"Cfg set VMs: {cfg_vpc_names}")
                    self.logger.info(f"VPCs already exist. Skipping VPC-Subnet creation. "
                                     f"Ignoring Launch section: {config_set}")
                    continue
                else:
                    subnet_count = config.as_int("SUBNETS")
                    if "SUBNET_NAME_SUFFIXES" in config:
                        subnet_names = config.as_list("SUBNET_NAME_SUFFIXES")
                        if len(subnet_names) != subnet_count:
                            self.logger.error(
                                f"Config: SUBNET_NAME_SUFFIXES list should contain same number of items as "
                                f"in SUBNETS: {subnet_count}. Got {len(subnet_names)} subnets: {subnet_names}")
                    else:
                        subnet_names = None
                    for vpc_index, vpc_name in enumerate(cfg_vpc_names):
                        # check if this individual vpc exist
                        if vpc_name not in available_vpcs:
                            self.logger.info(f"Creating VPC: {vpc_name}")
                            # create vpc
                            vpc_config = common_vpc_config
                            vpc_config["name"] = vpc_name
                            # noinspection PyTypeChecker
                            vpc_config["description"] = f"Auto VPC Creation: {vpc_name}"
                            req = self.compute_client.networks().insert(project=self.project, body=vpc_config)
                            resp = req.execute()
                            if 'error' in resp:
                                raise Exception(resp["error"])
                            if resp["status"] == "DONE":
                                self.logger.info(f"VPC: {vpc_name} creation successful")
                            else:
                                operation_id = resp["id"]
                                # global operation
                                if self.wait_on_operation(params={"operation_id": operation_id}):
                                    self.logger.info(f"VPC: {vpc_name} creation successful")
                                else:
                                    self.logger.error("VPC creation failed. Exit!")
                                    sys.exit(1)

                            # create subnets
                            operation_ids = []
                            regions = config.as_list("REGIONS")
                            vpc_cidr = config.as_list("VPC_CIDR")[vpc_index]
                            same_region = False
                            if len(regions) == 1:
                                same_region = True
                            else:
                                if len(regions) != subnet_count:
                                    self.logger.error(f"RegionMismatchError: Regions provided in the launch section "
                                                      f"does not match subnet count: {subnet_count}")

                            for i in range(1, subnet_count+1):
                                cidr_octets = vpc_cidr.split(".")
                                cidr_octets[2] = str(i)
                                cidr_octets[3] = "0/24"
                                subnet_cidr = ".".join(cidr_octets)
                                region = regions[0] if same_region else regions[i-1]
                                if not subnet_names:
                                    subnet_name = f"{vpc_name}-subnet-{i}-{region}"
                                else:
                                    subnet_name = f"{vpc_name}-{subnet_names[i-1]}"
                                self.logger.info(f"Creating subnet: {subnet_name} under vpc: {vpc_name}")
                                subnet_config = common_subnet_config
                                subnet_config["name"] = subnet_name
                                subnet_config["network"] = self.compute_base_url + "global/networks/" + vpc_name
                                subnet_config["region"] = region
                                subnet_config["ipCidrRange"] = subnet_cidr
                                request = self.compute_client.subnetworks().insert(project=self.project, region=region,
                                                                                   body=subnet_config)
                                resp = request.execute()
                                if 'error' in resp:
                                    raise Exception(resp["error"])
                                if resp["status"] == "DONE":
                                    self.logger.info(f"VPC: {vpc_name} creation successful")
                                else:
                                    operation_id = resp["id"]
                                    operation_ids.append((subnet_name, region, operation_id))
                            for subnet_name, region, operation_id in operation_ids:
                                self.logger.info(f"Waiting for subnet creation operation for subnet: {subnet_name} "
                                                 f"to complete")
                                # regional operation
                                if self.wait_on_operation(params={"operation_id": operation_id, "region": region},
                                                          operation_type='regional'):
                                    self.logger.info(f"Subnet:{subnet_name} creation successful under vpc: {vpc_name}")
                                else:
                                    self.logger.error(f"Subnet: {subnet_name} creation failed. Exit!")
                                    sys.exit(1)
                        else:
                            self.logger.info(f"Skipping VPC creation for existing VPC: {vpc_name}")
                if vpc_peering is not None:
                    self.logger.info("Identified VPC Peering configuration in cfg file, initiating VPC Peering setup")
                    available_vpc_subnets = self.get_all_vpc_subnets()
                    available_vpcs = set(available_vpc_subnets.keys())
                    for vpc_dir_set in vpc_peering:
                        vpc_network, peered_vpc = vpc_dir_set.split("->")
                        if vpc_network in available_vpcs and peered_vpc in available_vpcs:
                            self.create_vpc_peering(vpc_name=vpc_network, peered_vpc_name=peered_vpc)
                    self.logger.info("All VPC peerings created successfuly")

    @access_token_validator
    def delete_vpc(self, vpc_name, wait=False, project=None):
        """

        :param vpc_name:
        :param wait:
        :return:
        """
        if project is None:
            project = self.project
        # need to delete all resources of this vpc before proceeding to delete the vpc - GCE limitation
        # need to fetch all the resources pointing to the vpc in context
        # should use separate functions for each kind of resource
        self.logger.info(f"Deleting VPC: {vpc_name}")
        compute_base_url = self._compute_base_url_for_project(project=project)
        url = f"{compute_base_url}global/networks/{vpc_name}"
        payload = dict()
        payload["url"] = url
        payload["headers"] = self.headers
        resp = self.rest_ops.delete_query(payload=payload).json()
        if 'error' in resp:
            self.logger.error(f"Delete Operation on vpc: {vpc_name} failed")
            raise Exception(resp["error"])
        else:
            operation_id = resp["id"]
            # global operation
            if wait:
                if self.wait_on_operation(params={"operation_id": operation_id, "project": project}):
                    self.logger.info(f"VPC: {vpc_name} creation successful")
                else:
                    self.logger.error("VPC creation failed. Exit!")
                    sys.exit(1)
            else:
                return operation_id

    @access_token_validator
    def delete_subnet(self, subnet_config, wait=False, project=None):
        """

        :param subnet_config: A dictionary
        :param wait:
        :return: (subnet_name, region, operation_id) if wait is False
        """
        if project is None:
            project = self.project
        url = subnet_config.get("url", None)
        if url is None:
            # I can take URL directly or build an url from the config
            region = subnet_config["region"]
            subnet_name = subnet_config["name"]
            compute_base_url = self._compute_base_url_for_project(project=project)
            url = f"{compute_base_url}regions/{region}/subnetworks/{subnet_name}"
        else:
            url_split = url.split("/")
            subnet_name = url_split[-1]
            region = url_split[url_split.index("regions") + 1]
        self.logger.info(f"Deleting subnet: {subnet_name}")
        payload = dict()
        payload["url"] = url
        payload["headers"] = self.headers
        resp = self.rest_ops.delete_query(payload=payload).json()
        if 'error' in resp:
            self.logger.error(f"Delete Operation on subnet: {subnet_name} failed")
            raise Exception(resp["error"])
        else:
            operation_id = resp["id"]
            if wait:
                if self.wait_on_operation(params={"operation_id": operation_id, "region": region, "project": project},
                                          operation_type='regional'):
                    self.logger.info(f"Subnet:{subnet_name} deletion successful")
                else:
                    self.logger.error("Subnet deletion failed")
                    sys.exit(1)
            else:
                return subnet_name, region, operation_id

    def create_vpc_peering(self, vpc_name, peered_vpc_name, peering_name: str = None, **kwargs):
        """
        Create VPC - VPC Peering
        :param vpc_name:
        :param peered_vpc_name:
        :param peering_name: str

        {
            "name": string,
            "peerNetwork": string,
            "networkPeering": {
            "name": string,
            "network": string,
            "peerMtu": integer
            "exportCustomRoutes": boolean,
            "importCustomRoutes": boolean,
            "exchangeSubnetRoutes": boolean: true,
            "exportSubnetRoutesWithPublicIp": boolean,
            "importSubnetRoutesWithPublicIp": boolean,
            }
        }
        :return:
        """
        vpc_config = dict()
        vpc_config["name"] = peering_name if peering_name is not None else f"{vpc_name}-{peered_vpc_name}-peering"
        vpc_config["peerNetwork"] = vpc_name
        vpc_config["network_peering"] = kwargs
        vpc_config["network_peering"]["network"] = peered_vpc_name
        vpc_config["network_peering"]["name"] = vpc_config["name"]
        vpc_config["network_peering"]["exchangeSubnetRoutes"] = True

        self.logger.info(f"Create VPC Peering: {vpc_name} --> {peered_vpc_name}")
        req = self.compute_client.networks().addPeering(project=self.project, network=vpc_name, body=vpc_config)
        resp = req.execute()
        if 'error' in resp:
            raise Exception(resp["error"])
        if resp["status"] == "DONE":
            self.logger.info(f"VPC Peering: {vpc_name} --> {peered_vpc_name} creation successful")
        else:
            operation_id = resp["id"]
            # global operation
            if self.wait_on_operation(params={"operation_id": operation_id}):
                self.logger.info(f"VPC Peering: {vpc_name} --> {peered_vpc_name} creation successful")
            else:
                self.logger.error(f"VPC Peering: {vpc_name} --> {peered_vpc_name} creation failed. Exit!!")
                sys.exit(1)

    def list_all_vpc_peerings(self, vpc_names: list = None, config_vpcs: bool = True):
        """

        :param vpc_names:
        :param config_vpcs:
        :return: {vpc_name: {peered_vpc_name: vpc_peering_name}
        """
        self.logger.info("List VPC peering information")
        vpc_objects = dict()
        vpc_peerings = {}
        if vpc_names is None:
            if config_vpcs:
                vpc_names = self.config["GCP-EC2"].as_list("VPC_IDS")
            else:
                self.logger.warning("No VPCs provided to list vpc peering information")
                return vpc_peerings
        for vpc_name in vpc_names:
            vpc_objects.update(self.get_all_vpc_subnets(query_filter=f'name={vpc_name}', ret_obj=False))
        vpc_names = vpc_objects.keys()

        for vpc_name in vpc_names:
            self.logger.info(f"Fetching peering information for vpc: {vpc_name}")
            vpc_peerings[vpc_name] = {}
            if "peerings" in vpc_objects[vpc_name]:
                self.logger.info(f"VPC peers found for vpc: {vpc_name}")
                for peering in vpc_objects[vpc_name]["peerings"]:
                    vpc_peerings[vpc_name][peering["network"]] = peering["name"]
        self.logger.info("Collected all vpc peering information for the provided vpcs")
        return vpc_peerings

    def delete_vpc_peerings(self, vpc_name, peering_names: list = None, peered_vpc_name=None):
        if peering_names is None:
            peering_names = []
            if vpc_name is None:
                self.logger.error("At least peering_names or vpc_name needs to be provided")
                sys.exit(1)
            vpc_peerings = self.list_all_vpc_peerings(vpc_names=[vpc_name])[vpc_name]
            if peered_vpc_name is not None:
                peering_names.append(vpc_peerings[peered_vpc_name])
            else:
                peering_names = list(vpc_peerings.values())
        for peering_name in peering_names:
            self.logger.info(f"Remove VPC Peering: {peering_name}")
            remove_peering_config = {"name": peering_name}
            req = self.compute_client.networks().removePeering(project=self.project, network=vpc_name,
                                                               body=remove_peering_config)
            resp = req.execute()
            if 'error' in resp:
                raise Exception(resp["error"])
            if resp["status"] == "DONE":
                self.logger.info(f"VPC Peering: {peering_name} removed successfully")
            else:
                operation_id = resp["id"]
                # global operation
                if self.wait_on_operation(params={"operation_id": operation_id}):
                    self.logger.info(f"VPC Peering: {peering_name} removed successfully")
                else:
                    self.logger.error(f"VPC Peering: {peering_name} removal failed. Exit!!")
                    sys.exit(1)

    @access_token_validator
    def get_vpc_instances(self, vpc_name, ignore_status=False, instance_filter=None, fetch_ips=False,
                          is_spot_enabled=False, fetch_names=False):
        """
        Fetch instances per vpc
        :param vpc_name: name of a single vpc or regex of multiple vpcs
        :param instance_filter: labels ("labels.type=test-vm")
        :param ignore_status: bool
        :param fetch_ips: bool: False (default), if set to True: this function fetches ips of VMs
        :param is_spot_enabled: bool: False (default), if set to True, then only spot instances will be returned
        :param fetch_names: bool: False (default), if set to True, returns a list of instance names
        :return:
        """
        payload = dict()
        payload["headers"] = self.headers
        payload["params"] = None
        vpc_objects = self.get_all_vpc_subnets(query_filter=f'name={vpc_name}')
        ip_dict = dict()
        instances = []
        zone_dict = {}
        for vpc_name in vpc_objects:
            vpc_subnets = vpc_objects[vpc_name]
            subnets = vpc_subnets["subnetworks"]
            for subnet in subnets:
                subnet_obj = subnet.get_object()
                payload["url"] = subnet_obj.execute()["region"]
                subnet_region_zones = GetObject(payload=payload, rest_ops=self.rest_ops).get_object()["zones"]
                # subnet_region_zones = self.rest_ops.get_query(payload=payload)["zones"]
                subnet_region_zones = [zone.split("zones/")[1] for zone in subnet_region_zones]
                for zone in subnet_region_zones:
                    zone_dict[zone] = zone_dict.get(zone, set())
                    zone_dict[zone].add(vpc_name)  # now I have mapping with zone and vpc and no duplicate in zones
        for zone, vpc_names in zone_dict.items():
            req = self.compute_client.instances().list(project=self.project, zone=zone, filter=instance_filter)
            while req is not None:
                resp = req.execute()
                items = resp.get("items", None)
                if items is not None:
                    for instance in items:
                        if instance["status"] != "RUNNING" and not ignore_status:
                            self.logger.debug(f"Skipping instance: {instance['name']}\n\t"
                                              f"instance_state: {instance['status']}")
                            continue
                        if is_spot_enabled:
                            instance_scheduling = instance.get("scheduling", None)
                            if instance_scheduling:
                                preemptible = instance_scheduling.get("preemptible", False)
                                if not preemptible:
                                    continue
                        for interface in instance["networkInterfaces"]:
                            vpc_name = interface["network"].split("networks/")[1]
                            # actually I don't need this below check since I changed the logic... lazy to remove it
                            if vpc_name in vpc_names:
                                if not fetch_ips:
                                    if fetch_names:
                                        instance = instance['name']
                                    instances.append(instance)
                                else:
                                    private_ip = interface["networkIP"]
                                    public_ip = interface["accessConfigs"][0]["natIP"]
                                    ip_dict[vpc_name] = ip_dict.get(vpc_name, [])
                                    ip_dict[vpc_name].append((public_ip, private_ip))
                                break
                req = self.compute_client.instances().list_next(previous_request=req, previous_response=resp)
        if fetch_ips:
            return ip_dict
        return instances

    @access_token_validator
    def get_image(self, image_name, image_project):
        self.logger.info(f"Fetching Image matching: {image_name} from Project: {image_project}")
        if any([image_name is None, image_project is None]):
            self.logger.error("Either image_name or image_project parameter supplied is a NoneType variable")
            sys.exit(1)
        else:
            payload = dict()
            payload["url"] = \
                f"https://www.googleapis.com/compute/v1/projects/{image_project}/global/images/{image_name}"
            payload["headers"] = self.headers
            resp = self.rest_ops.get_query(payload=payload)
            return resp

    def segregate_public_and_private_deployable_subnets(self, subnets, deployable_subnets, deployable_subnets_private):
        public_subnets = []
        private_subnets = []
        if len(deployable_subnets) != 0 or len(deployable_subnets_private) != 0:
            for subnet in subnets:
                # subnet = subnet.split(self.compute_base_url)[1]
                subnet_name = subnet.split("/")[-1]
                skip_public = True
                skip_private = True

                self.logger.info(f"Checking if subnet: {subnet_name} endswith any subnet in DEPLOYABLE_SUBNETS")
                if len(deployable_subnets) != 0 and subnet_name.endswith(deployable_subnets):
                    skip_public = False
                    public_subnets.append(subnet)
                elif len(deployable_subnets_private) != 0 and subnet_name.endswith(deployable_subnets_private):
                    skip_private = False
                    private_subnets.append(subnet)
                if skip_public and skip_private:
                    self.logger.warn(f"Skipping subnet: {subnet_name}. No matching subnet found in "
                                     f"DEPLOYABLE_SUBNETS or DEPLOYABLE_SUBNETS_PRIVATE")
                    continue
        return public_subnets, private_subnets

    @access_token_validator
    def launch_instances(self, launch_config=None):
        """

        :param launch_config: is a dict of dicts that contain the following attributes from the LAUNCH section of the
        config file:
        { ENABLE, LABELS, INSTANCE_TYPE, IMAGE_NAME, IMAGE_PROJECT, TAGS, VPCS, NAME_PREFIX, ZONES, COUNT, TOTAL_COUNT }
        :return:
        """
        if launch_config is None:
            launch_config = self.config["GCP-EC2"]["LAUNCH"]
        operation_ids = []
        payload = dict()
        payload["headers"] = self.headers
        install_script_location = self.config["GCP-EC2"]["INSTALL_SCRIPT"]
        with open(install_script_location, 'r') as f:
            install_script = f.read()
        user = self.config["GCP-EC2"]["USER"]
        ssh_key = user + ":" + self.config["GCP-EC2"]["PUBLIC_KEY"]
        instance_filter = self.config["GCP-EC2"]["FILTER"]
        is_spot_enabled = self.config["GCP-EC2"].get("ENABLE_SPOT_INSTANCE", False)
        if is_spot_enabled is not False:
            is_spot_enabled = self.config["GCP-EC2"].as_bool("ENABLE_SPOT_INSTANCE")
        for config_set in launch_config:
            config = launch_config[config_set]
            if 'ENABLE' not in config or config.as_bool("ENABLE") is False:
                self.logger.info(f"Skipping config: {config_set} - Not enabled.")
                continue
            if config.as_bool("TOOL_ENABLE") is True:
                install_script_location = self.config["GCP-EC2"]["TOOL_INSTALL_SCRIPT"]
                with open(install_script_location, 'r') as f:
                    install_script = f.read()
            self.logger.info(f"Using Config: {config_set}\n")
            label_dict = dict()
            labels = config.as_list("LABELS")
            for i in labels:
                label = i.split("=")
                label_dict[label[0]] = label[1]
            instance_type = config["INSTANCE_TYPE"]
            image_name = config["IMAGE_NAME"]
            image_project = config["IMAGE_PROJECT"]
            can_ip_forward = False
            image_url = self.get_image(image_name=image_name, image_project=image_project)["selfLink"]
            tags = config.as_list("TAGS")
            vpcs = config.as_list("VPCS")
            deployable_zones = config.as_list("ZONES")
            if "DEPLOYABLE_SUBNETS" in config:
                deployable_subnets = tuple(config.as_list("DEPLOYABLE_SUBNETS"))
            else:
                deployable_subnets = tuple()

            if "DEPLOYABLE_SUBNETS_PRIVATE" in config:
                deployable_subnets_private = tuple(config.as_list("DEPLOYABLE_SUBNETS_PRIVATE"))
            else:
                deployable_subnets_private = tuple()
            public_vm_count = config.as_int("COUNT")
            private_vm_count = config.as_int("PRIVATE_VM_COUNT") if "PRIVATE_VM_COUNT" in config else 0
            if public_vm_count == 0 and private_vm_count == 0:
                self.logger.info(f"No VM created in {vpcs} as the vm count is set to 0")
                return True
            # if private_vm_count > 0 and deployable_subnets_private == 0:
            #     self.logger.info("Private Instances can not be deployed without DEPLOYABLE_SUBNETS_PRIVATE")
            total_vms = config.as_int("TOTAL_COUNT")
            total_vms = total_vms if total_vms != -1 else None
            if total_vms:
                if public_vm_count + private_vm_count > total_vms:
                    self.logger.error("Private VM count and Public VM count should be bound by Total VM Count")
                    self.logger.error("Check config and correct the COUNT and PRIVATE_VM_COUNT variables "
                                      "to match with TOTAL_COUNT or change TOTAL_COUNT to sum of COUNT+PRIVATE_VM_COUNT"
                                      "or set to -1 to launch desired number of VMs as needed per subnet found in VPCs")
                    sys.exit(1)
            # loop over region matching zones - deploy vm alternatively until the condition is satisfied
            deployed_vm_count = 0
            for vpc in vpcs:
                threshold = False
                available_vpc_instances = self.get_vpc_instances(
                    vpc_name=vpc, ignore_status=True, instance_filter=instance_filter, is_spot_enabled=is_spot_enabled,
                    fetch_names=True)
                self.logger.info(f"Creating VMs in {vpc}")
                
                vpc_objects = self.get_all_vpc_subnets(query_filter=f'name={vpc}',
                                                        ret_obj=False)  # get urls of subnets
                # get subnets in the vpc
                _subnets = vpc_objects[vpc]["subnetworks"]

                vpc_vm_count = 0
                public_subnets, private_subnets = self.segregate_public_and_private_deployable_subnets(
                    subnets=_subnets, deployable_subnets=deployable_subnets,
                    deployable_subnets_private=deployable_subnets_private)

                # this helps to pick all the subnets for VM launch if in case of deployable_subnets are not provided
                if len(public_subnets) == 0 and public_vm_count > 0 and len(deployable_subnets) == 0:
                    public_subnets = _subnets

                # helps to pick all subnets for private VM launch if the deployable_subnets_private is not provided
                if len(private_subnets) == 0 and private_vm_count > 0 and len(deployable_subnets_private) == 0:
                    private_subnets = _subnets

                for subnet_category, subnets in [("public", public_subnets), ("private", private_subnets)]:
                    instance_name_prefix = config["NAME_PREFIX"]
                    instance_name_prefix += subnet_category + "-"
                    for subnet in subnets:
                        if threshold:
                            # self.logger.info("Hit VM Threshold; Skipping Subnet")
                            break
                        
                        subnet = subnet.split(self.compute_base_url)[1]
                        vm_count = public_vm_count if subnet_category == "public" else private_vm_count
                        if subnet_category == "private":
                            network_interfaces = [{"kind": "compute#networkInterface",
                                                    "subnetwork": subnet, "stackType": "IPV4_ONLY",
                                                    }]
                        else:
                            network_interfaces = [{"kind": "compute#networkInterface",
                                                    "subnetwork": subnet,
                                                    "accessConfigs": [{"kind": "compute#accessConfig",
                                                                        "name": "External NAT",
                                                                        "type": "ONE_TO_ONE_NAT",
                                                                        "networkTier": "PREMIUM"}],
                                                    "aliasIpRanges": []}]
                        region = subnet.split("/")[1]
                        zones = [zone for zone in deployable_zones if zone.startswith(region)]
                        # if there is no deployable zone in this subnet - skip this subnet
                        if len(zones) == 0:
                            self.logger.warn(f"Skipping Subnet: {subnet}."
                                             f"No deployable zone found that matches the subnet region: {region}")
                            continue
                        # round-robin algorithm on zones list - generator object
                        zone_gen = RORO(zones, vm_count).round_robin()
                        for i in range(vm_count):
                            zone = next(zone_gen)
                            if total_vms is not None and vpc_vm_count >= total_vms:
                                threshold = True
                                break
                            vpc_vm_count += 1
                            deployed_vm_count += 1
                            instance_name = instance_name_prefix + str(deployed_vm_count).zfill(2)
                            if instance_name in available_vpc_instances:
                                self.logger.info(f"Instance: {instance_name} already exists! Skipping VM creation.")
                                continue
                            vm_config: dict = {"name": instance_name, "zone": zone,
                                               "machineType": f"zones/{zone}/machineTypes/{instance_type}",
                                               "metadata": {"kind": "compute#metadata",
                                                            "items": [{"key": "startup-script",
                                                                       "value": install_script},
                                                                      {"key": "ssh-keys",
                                                                       "value": ssh_key}]
                                                            },
                                               "tags": {"items": tags},
                                               "disks": [{
                                                   "type": "PERSISTENT", "boot": True, "mode": "READ_WRITE",
                                                   "autoDelete": True, "deviceName": instance_name,
                                                   "initializeParams": {"sourceImage": image_url, "diskSizeGb": "10"}}],
                                               "canIpForward": can_ip_forward,
                                               "networkInterfaces": network_interfaces,
                                               "labels": label_dict,
                                               "reservationAffinity": {"consumeReservationType": "ANY_RESERVATION"},
                                               "serviceAccounts": [{"email": self.credentials.service_account_email,
                                                                    "scopes": self.credentials.scopes}],
                                               "confidentialInstanceConfig": {"enableConfidentialCompute": False}}
                            if is_spot_enabled:
                                vm_config["scheduling"] = {'preemptible': True}
                            payload["url"] = f"{self.compute_base_url}zones/{zone}/instances"
                            payload["data"] = json.dumps(vm_config)
                            resp = self.rest_ops.post_query(payload=payload).json()
                            if resp["status"] != "DONE":
                                params = dict()
                                params["operation_id"] = resp["id"]
                                params["zone"] = zone
                                operation_ids.append(params)
        for params in operation_ids:
            if self.wait_on_operation(operation_type="zonal", params=params):
                self.logger.info(f"Operation: {params['operation_id']} is successful")
            else:
                self.logger.error(f"Operation: {params['operation_id']} failed..")
                sys.exit(1)
        self.logger.info("All VMs created successfully")
        return True

    @access_token_validator
    def deploy_instances(self, kwargs_dict_list):
        """
        :param kwargs_dict_list: list of kwargs_dicts
        :return:
        """
        operation_ids = []
        for kwargs in kwargs_dict_list:
            required_params = {"instance_name", "instance_type", "install_script", "ssh_key", "tags", "zone",
                               "image_url", "subnet", "label_dict", "is_spot_enabled"}
            if not required_params.issubset(set(kwargs.keys())):
                self.logger.error(f"Missing required parameters: {required_params.difference(set(kwargs.keys()))}")
                sys.exit(1)
            vm_config: dict = {"name": kwargs["instance_name"], "zone": kwargs["zone"],
                               "machineType": f"zones/{kwargs['zone']}/machineTypes/{kwargs['instance_type']}",
                               "metadata": {"kind": "compute#metadata",
                                            "items": [{"key": "startup-script", "value": kwargs["install_script"]},
                                                      {"key": "ssh-keys", "value": kwargs["ssh_key"]}]
                                            },
                               "tags": {"items": kwargs["tags"]},
                               "disks": [{
                                   "type": "PERSISTENT", "boot": True, "mode": "READ_WRITE",
                                   "autoDelete": True, "deviceName": kwargs["instance_name"],
                                   "initializeParams": {"sourceImage": kwargs["image_url"], "diskSizeGb": "10"}}],
                               "canIpForward": False,
                               "networkInterfaces": [{"kind": "compute#networkInterface",
                                                      "subnetwork": kwargs["subnet"],
                                                      "accessConfigs": [{"kind": "compute#accessConfig",
                                                                         "name": "External NAT",
                                                                         "type": "ONE_TO_ONE_NAT",
                                                                         "networkTier": "PREMIUM"}],
                                                      "aliasIpRanges": []}],
                               "labels": kwargs["label_dict"],
                               "reservationAffinity": {"consumeReservationType": "ANY_RESERVATION"},
                               "serviceAccounts": [{"email": self.credentials.service_account_email,
                                                    "scopes": self.credentials.scopes}],
                               "confidentialInstanceConfig": {"enableConfidentialCompute": False}}
            if kwargs["is_spot_enabled"]:
                vm_config["scheduling"] = {'preemptible': True}
            payload = dict()
            payload["headers"] = self.headers
            payload["url"] = f"{self.compute_base_url}zones/{kwargs['zone']}/instances"
            payload["data"] = json.dumps(vm_config)
            resp = self.rest_ops.post_query(payload=payload).json()
            if resp["status"] != "DONE":
                params = dict()
                params["operation_id"] = resp["id"]
                params["zone"] = kwargs['zone']
                operation_ids.append(params)
        for params in operation_ids:
            if self.wait_on_operation(operation_type="zonal", params=params):
                self.logger.info(f"Operation: {params['operation_id']} is successful")
            else:
                self.logger.error(f"Operation: {params['operation_id']} failed..")
                sys.exit(1)
        self.logger.info("All VMs created successfully")
        return True

    @access_token_validator
    def instance_operations(self, operation_typ, vpcs=None, instance_filter=None, instances=None, use_tool=False):
        """
        Start/stop/delete all the instances in the VPC
        :param operation_typ: str: should be one of [start, stop, delete]
        :param vpcs: list:
        :param instance_filter:
        :param instances:
        :param use_tool:
        :return:
        """
        op_typs = {"start", "stop", "delete"}
        if operation_typ not in op_typs:
            self.logger.error(f"operation_typ provided: {operation_typ} should be one of {op_typs}")
        self.logger.info("Fetching all instance in the vpcs provided")
        if instances is None:
            if vpcs is None:
                vpcs = self.config["GCP-EC2"].as_list("VPC_IDS") if not use_tool else \
                    self.config["GCP-EC2"].as_list("TOOL_VPC_IDS")
            is_spot_enabled = self.config["GCP-EC2"].get("ENABLE_SPOT_INSTANCE", False)
            if is_spot_enabled is not False:
                is_spot_enabled = self.config["GCP-EC2"].as_bool("ENABLE_SPOT_INSTANCE")
            if instance_filter is None:
                instance_filter = self.config["GCP-EC2"].as_list("FILTER") if not use_tool else \
                    self.config["GCP-EC2"].as_list("TOOL_FILTER")
                if instance_filter == [""] or instance_filter == []:
                    instance_filter = None
                else:
                    instance_filter = instance_filter[0] if len(instance_filter) == 1 else " AND ".join(instance_filter)
            instances = []
            for vpc in vpcs:
                instances.extend(self.get_vpc_instances(vpc_name=vpc, ignore_status=True,
                                                        instance_filter=instance_filter,
                                                        is_spot_enabled=is_spot_enabled))
        operation_ids = []
        params = dict()
        for instance in instances:
            if operation_typ == "start" and instance["status"] == "RUNNING":
                continue
            elif operation_typ == "stop" and instance["status"] != "RUNNING":
                continue
            instance_name = instance["name"]
            zone = instance["zone"].split("zones/")[1]
            if operation_typ != "delete":
                url = f"{self.compute_base_url}zones/{zone}/instances/{instance_name}/{operation_typ}"
            else:
                url = f"{self.compute_base_url}zones/{zone}/instances/{instance_name}"
            payload = dict()
            payload["url"] = url
            payload["headers"] = self.headers
            if operation_typ != "delete":
                payload["data"] = None
                resp = self.rest_ops.post_query(payload=payload).json()
            else:
                resp = self.rest_ops.delete_query(payload=payload).json()
            if resp["status"] != "DONE":
                operation_ids.append((resp["id"], zone))
            else:
                self.logger.info(f" {operation_typ} operation on instance: {resp['name']} successful")
        for oz in operation_ids:
            params["operation_id"] = oz[0]
            params["zone"] = oz[1]
            if self.wait_on_operation(params=params, operation_type="zonal"):
                self.logger.info(f"{operation_typ} VM Operation: {oz[0]} successful")
            else:
                self.logger.error(f"{operation_typ} VM Operation: {oz[0]} failed")
                sys.exit(1)
        self.logger.info(f"All VMs {operation_typ}ed")
        return True

    def cleanup_infra(self, vpcs=None, use_tool=False):
        self.logger.info("Cleanup Infra: VPCs, Subnets and Instances")
        self.instance_operations(operation_typ="delete", vpcs=vpcs)
        if vpcs is None:
            vpcs = self.config["GCP-EC2"].as_list("VPC_IDS") if not use_tool else \
                self.config["GCP-EC2"].as_list("TOOL_VPC_IDS")

        vpc_subnets = dict()
        operation_ids = []
        for vpc_name in vpcs:
            vpc_subnets.update(self.get_all_vpc_subnets(query_filter=f'name={vpc_name}', ret_obj=False))
        for vpc in vpc_subnets:
            subnets = vpc_subnets[vpc].get("subnetworks", [])
            peerings = vpc_subnets[vpc].get("peerings", [])
            for subnet in subnets:
                operation_ids.append(self.delete_subnet(subnet_config={"url": subnet}))
            for subnet_name, region, operation_id in operation_ids:
                if self.wait_on_operation(params={"operation_id": operation_id, "region": region},
                                          operation_type='regional'):
                    self.logger.info(f"Subnet:{subnet_name} deletion successful")
                else:
                    self.logger.error("Subnet deletion failed")
                    sys.exit(1)
            peering_names = [peerings[i]["name"] for i in peerings]
            self.delete_vpc_peerings(vpc_name=vpc, peering_names=peering_names)
            self.delete_vpc(vpc_name=vpc, wait=True)
        self.logger.info("Finished infrastructure cleanup!")
        return True

    def get_instance(self, zone, instance_name, project=None):
        """
        get instance
        :param zone:
        :param instance_name:
        :param project:
        :return:
        """
        if project is None:
            project = self.project
        self.logger.info(f"Get instance with name: {instance_name} deployed in zone: {zone} under project: {project}")
        try:
            request = self.compute_client.instances().get(project=project, zone=zone, instance_name=instance_name)
            response = request.execute()
        except Exception as e:
            self.logger.error(f"Exception while fetching instance: {instance_name}: {e}")
            sys.exit(1)
        else:
            if response.get("name", None) is None:
                self.logger.error(f"Got empty response for request to get instance: {instance_name}.resp: {response}")
                sys.exit(1)
            else:
                return response

    def get_all_instance_ips(self, vpcs=None, vm_prefix=None, use_tool=False):
        """
        fetch private and public IP of each instance associated with VPC.
        GCE API is too raw as it doesnt contain any association with VPC and instance except that the network is
        mentioned in the instance metadata - but it still needs a full iteration of all instances.
        So, I limit the iterations by fetching the subnets associated with vpcs and then zones in each subnet then map
        the vpcs and zones
        :param vpcs:
        :param vm_prefix: by default uses the FILTER parameter from the config
        :param use_tool: default- False
        :return:
        """
        self.logger.info("Fetching all instance IPs for the vpcs provided")
        if vpcs is None:
            if use_tool:
                vpcs = self.config["GCP-EC2"].as_list("TOOL_VPC_IDS")
            else:
                vpcs = self.config["GCP-EC2"].as_list("VPC_IDS")
        is_spot_enabled = self.config["GCP-EC2"].get("ENABLE_SPOT_INSTANCE", False)
        if is_spot_enabled is not False:
            is_spot_enabled = self.config["GCP-EC2"].as_bool("ENABLE_SPOT_INSTANCE")
        # default filter for test-vms
        if vm_prefix is None:
            instance_filter = self.config["GCP-EC2"].as_list("FILTER") if not use_tool else \
                self.config["GCP-EC2"].as_list("TOOL_FILTER")
            if instance_filter == [""] or instance_filter == []:
                instance_filter = None
            else:
                instance_filter = instance_filter[0] if len(instance_filter) == 1 else " AND ".join(instance_filter)
        else:
            instance_filter = vm_prefix
        ip_dict = OD()
        for vpc in vpcs:
            self.logger.info(f"Processing vpc: {vpc}")
            ip_dict.update(self.get_vpc_instances(vpc_name=vpc, fetch_ips=True, instance_filter=instance_filter,
                                                  is_spot_enabled=is_spot_enabled))
        return ip_dict

    def entity_mixer(self, ip_dict: dict, entities: list) -> list:
        res_vm_mix = []
        vms_cluster = []
        max_length = 0
        for entity in entities:
            entity_vms = ip_dict[entity]
            max_length = max(len(entity), max_length)
            vms_cluster.append(entity_vms)

        for i in range(max_length):
            for idx, vm_list in enumerate(vms_cluster):
                if len(vm_list) != 0:
                    vm = vm_list.pop()
                    res_vm_mix.append(vm)
                    vms_cluster[idx] = vm_list
        return res_vm_mix

    def process_entities(self, client_entities: list, server_entities: list, ip_dict: dict):
        if client_entities == "ALL" and server_entities == "ALL":
            self.logger.error("Mapping is incorrect: only one of the client or server may contain ALL")
            sys.exit(1)
        total_entities_set = set(ip_dict.keys())
        if client_entities == "ALL" or server_entities == "ALL":
            if client_entities == "ALL":
                client_entities = list(total_entities_set.difference(set(server_entities)))
            else:
                # server_entities == "ALL"
                server_entities = list(total_entities_set.difference(set(client_entities)))
        return client_entities, server_entities

    def enforce_mapping(self, mapping: str, ip_dict: dict):
        """
        :param mapping:
        :param ip_dict:
        :return:
        """
        correct_mapping_format = """
        TRAFFIC_MAPPING = "vamsi-VPC1-->vamsi-vpc2" or you can specify "<vpc name>-->ALL" or "ALL--><vpc name>" or 
        "None" or "VPC1,VPC2-->VPC3" and vice versa; only used when single cloud is specified
        or specify "VPC1-->VPC2;VPC3-->VPC4,VPC5;VPC6-->VPC7"  --> separate mappings are delimited using ';'
        """
        client_server_vm_dict = dict()
        identifier = "-->"
        multi_mapping_identifier = ";"
        if mapping.count(identifier) == 0:
            self.logger.error(f"Error parsing the mapping. Incorrect mapping detected: {mapping}")
            self.logger.info(f"Mapping should be in one of the formats specified here: {correct_mapping_format}")
            sys.exit(1)
        if mapping.count(identifier) > 1:
            if multi_mapping_identifier in mapping:
                mapping_list = mapping.split(multi_mapping_identifier)
            else:
                self.logger.info(f"Mapping should be in one of the formats specified here: {correct_mapping_format}")
                sys.exit(1)
        else:
            mapping_list = [mapping]

        for mapping in mapping_list:
            client_entities, server_entities = mapping.split(identifier)
            client_entities = client_entities.split(",")
            server_entities = server_entities.split(",")
            client_entities, server_entities = self.process_entities(client_entities=client_entities,
                                                                     server_entities=server_entities,
                                                                     ip_dict=ip_dict)
            client_vm_mix = self.entity_mixer(ip_dict=ip_dict, entities=client_entities)
            server_vm_mix = self.entity_mixer(ip_dict=ip_dict, entities=server_entities)
            for idx in range(min(len(client_vm_mix), len(server_vm_mix))):
                client_server_vm_dict[client_vm_mix[idx]] = server_vm_mix[idx]
        return client_server_vm_dict

    def create_client_server_mapping(self, direction="uni", use_tool=False, granularity="vpc", mapping=None,
                                     vm_prefix=None):
        """
        Maps the client and server ips and also makes sure that the ips belong to different VPCs
        leaves the excess IPs without mapping which all belong to the same VPC

        :param direction: default: "uni", if its "uni", one VPC is considered as the client VPC and the other as server
        :param use_tool: default: False, if true, fetches TOOL vms
        :param granularity: vpc: [vpc level bi-direction]; vm: vm level  [uses vms as clients and servers within vpc]
        :param mapping:
        :param vm_prefix:
        :return:
        """
        # contains VPC: IP mapping
        ip_dict = self.get_all_instance_ips(use_tool=use_tool, vm_prefix=vm_prefix)
        if mapping is None:
            vpcs: list = list(ip_dict.keys())
            if len(vpcs) <= 1:
                self.logger.error(f"At least 2 VPCs need to be provided. Provided: {len(vpcs)}")
                sys.exit(1)
            elif len(vpcs) > 2 and direction != "bi":
                self.logger.error("When multiple VPCs are used for testing, direction=uni can not be set")
                sys.exit(1)
            new_d = dict()
            if direction == "bi":
                i, j = 0, 1
                m_idx, n_idx = 0, 0
                prev_ip = None
                while (i <= len(vpcs) > j) and i < j:
                    vi, vj = vpcs[i], vpcs[j]
                    while m_idx < len(ip_dict[vi]) and n_idx < len(ip_dict[vj]):
                        mip, nip = ip_dict[vi][m_idx], ip_dict[vj][n_idx]
                        # to change client-server within the vpc when granularity set to vm level
                        if granularity == "vm" and (prev_ip and prev_ip == "mip"):
                            new_d[nip] = mip
                            prev_ip = "nip"
                        else:
                            new_d[mip] = nip
                            prev_ip = "mip"
                        m_idx += 1
                        n_idx += 1
                        if m_idx >= len(ip_dict[vi]) and n_idx < len(ip_dict[vj]):
                            i = j + 1
                            m_idx = 0
                            break
                        elif m_idx < len(ip_dict[vi]) and n_idx >= len(ip_dict[vj]):
                            j += 1
                            n_idx = 0
                            break
                        elif (m_idx == len(ip_dict[vi]) and n_idx <= len(ip_dict[vj])) or (
                                m_idx <= len(ip_dict[vi]) and n_idx == len(ip_dict[vj])):
                            if n_idx < len(ip_dict[vj]):
                                m_idx = 0
                                i = j + 1
                            if m_idx < len(ip_dict[vi]):
                                n_idx = 0
                                j += 1
                            else:
                                m_idx = 0
                                n_idx = 0
                                i = j + 1
                                j += i + 1
                            break
            else:
                client_vpc = vpcs[0]
                client_vms = ip_dict[client_vpc]
                server_vms = []
                [server_vms.extend(ip_dict[vpc]) for vpc in ip_dict if vpc != client_vpc]
                client_count = len(client_vms)
                server_count = len(server_vms)
                for i in range(client_count)[:server_count]:
                    new_d[client_vms[i]] = server_vms[i]
            print(new_d)
            return new_d
        else:
            return self.enforce_mapping(mapping=mapping, ip_dict=ip_dict)

    def get_firewall_rules(self):
        self.logger.info("Fetching all firewall rules in the project")
        firewall_rules = []
        req = self.compute_client.firewalls().list(project=self.project)
        while req is not None:
            resp = req.execute()
            for firewall_rule in resp['items']:
                firewall_rules.append(firewall_rule)
            req = self.compute_client.firewalls().list_next(previous_request=req, previous_response=resp)
        return firewall_rules

    

    @access_token_validator
    def add_or_delete_ingress_egress_firewall_rules(self, operation, launch_config=None):
        """
        function called after vpc creation and infra deletion
        :param operation: str: either 'create' or 'delete'
        :param launch_config = dict(dict)
        :return: None
        """
        if launch_config is None:
            launch_config = self.config["GCP-EC2"].get("LAUNCH", None)
        if launch_config is not None:
            for config_set in launch_config:
                config = launch_config[config_set]
                if 'ENABLE' in config and config.as_bool('ENABLE') is True:
                    vpcs = config.as_list("VPCS")
                    cidrs = config.as_list("VPC_CIDR")
                    common_ranges = config.as_list("FIREWALL_IP_RANGES")
                    common_ranges.extend(cidrs)
                    tags = config.as_list("TAGS")
                    rules = []
                    payload = dict()
                    payload["url"] = f"{self.compute_base_url}global/firewalls"
                    payload_url = payload["url"]
                    payload["headers"] = self.headers
                    operation_ids = []
                    if operation == 'create':
                        for vpc in vpcs:
                            ingress_rule = {"allowed": [{"IPProtocol": "all"}], "direction": "INGRESS",
                                            "name": f"{vpc}-ingress-rule",
                                            "network": f"{self.compute_base_url}global/networks/{vpc}",
                                            "priority": 1000.0,
                                            "sourceRanges": common_ranges, "targetTags": tags}
                            rules.append(ingress_rule)
                            egress_rule = {"allowed": [{"IPProtocol": "all"}], "destinationRanges": ["0.0.0.0/0"],
                                           "direction": "EGRESS", "name": f"{vpc}-egress-rule",
                                           "network": f"{self.compute_base_url}global/networks/{vpc}",
                                           "priority": 1000.0}
                            rules.append(egress_rule)
                    elif operation == 'delete':
                        for vpc in vpcs:
                            rules.extend([f"{vpc}-ingress-rule", f"{vpc}-egress-rule"])
                    if operation == 'create':
                        for rule in rules:
                            payload["data"] = json.dumps(rule)
                            resp = self.rest_ops.post_query(payload=payload).json()
                            if 'error' in resp:
                                self.logger.error(f"Creation of Firewall rule: {rule} failed!")
                                raise Exception(resp["error"])
                            else:
                                operation_ids.append(resp["id"])
                    elif operation == 'delete':
                        for rule in rules:
                            payload["url"] = payload_url + f"/{rule}"
                            resp = self.rest_ops.delete_query(payload=payload)
                            if resp is not None and 'error' in resp:
                                if resp['error']['code'] == 404:
                                    self.logger.warning(f"Not exiting since resource not found: {resp}")
                                    pass
                                else:
                                    self.logger.error(f"Deletion of Firewall rule: {rule} failed!")
                                    raise Exception(resp["error"])
                            else:
                                if resp is not None:
                                    resp = resp.json()
                                    operation_ids.append(resp["id"])
                    for operation_id in operation_ids:
                        if self.wait_on_operation(params={"operation_id": operation_id}):
                            self.logger.info(f"Firewall rule {operation} operation successful.Ops ID: {operation_id}")
                        else:
                            self.logger.error(f"Firewall Rule {operation} operation: {operation_id} failed. Exit!")
                            sys.exit(1)
            self.logger.info(f"All Firewall rules {operation}ed successfully")



if __name__ == "__main__":
    self = GoogleConnector()
    self.cost_report()
    # self.get_all_vpc_subnets()
    # self.get_vpc_instances(vpc_name="vamsi-vpc*", fetch_ips=True)
    # self.get_firewall_rules()
    # self.check_firewall_rules()
    # ips = self.get_all_instance_ips()
    # print(ips)
    # self.instance_operations(operation_typ="delete")
    # self.cleanup_infra()
    # self.create_vpc_subnets()
    # self.add_or_delete_ingress_egress_firewall_rules(operation='create')
    # self.add_or_delete_ingress_egress_firewall_rules(operation='delete')

