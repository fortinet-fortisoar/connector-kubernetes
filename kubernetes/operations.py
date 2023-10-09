""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError
from datetime import datetime
from requests import post
from os.path import join
from integrations.crudhub import make_request
from django.conf import settings
from kubernetes import utils
import kubernetes.client

try:
    from integrations.crudhub import download_file_from_cyops
except:
    from connectors.cyops_utilities.builtins import download_file_from_cyops

logger = get_logger('kubernetes')


def _upload_file_to_cyops(file_name, file_content, file_type):
    try:
        # Conditional import based on the FortiSOAR version.
        try:
            from integrations.crudhub import make_file_upload_request
            response = make_file_upload_request(file_name, file_content, 'application/octet-stream')

        except:
            from cshmac.requests import HmacAuth
            from integrations.crudhub import maybe_json_or_raise

            url = settings.CRUD_HUB_URL + '/api/3/files'
            auth = HmacAuth(url, 'POST', settings.APPLIANCE_PUBLIC_KEY,
                            settings.APPLIANCE_PRIVATE_KEY,
                            settings.APPLIANCE_PUBLIC_KEY.encode('utf-8'))
            files = {'file': (file_name, file_content, file_type, {'Expire': 0})}
            response = post(url, auth=auth, files=files, verify=False)
            response = maybe_json_or_raise(response)

        logger.info('File upload complete {0}'.format(str(response)))
        file_id = response['@id']
        time = datetime.now()
        file_description = 'Downloaded from CrowdStrike Falcon using connector at {time}'.format(time=time)
        attach_response = make_request('/api/3/attachments', 'POST',
                                       {'name': file_name, 'file': file_id, 'description': file_description})
        logger.info('attach file complete: {0}'.format(attach_response))
        return attach_response
    except Exception as err:
        logger.exception('An exception occurred {0}'.format(str(err)))
        raise ConnectorError('An exception occurred {0}'.format(str(err)))


def _create_cyops_attachment(file_name, content, description=''):
    attachment_name = file_name
    file_resp = _upload_file_to_cyops(attachment_name, content, 'application/octet-stream')
    return file_resp


def from_cyops_download_file(iri):
    try:
        file_name = None
        attachment_data = make_request(iri, 'GET')
        if iri.startswith('/api/3/attachments/'):
            file_iri = attachment_data['file']['@id']
            file_name = attachment_data['file']['filename']
            logger.info('file id = {0}, file_name = {1}'.format(file_iri, file_name))
        else:
            file_iri = iri
        dw_file_md = download_file_from_cyops(file_iri)
        file_path = join('/tmp', dw_file_md['cyops_file_path'])
        if file_name == None:
            file_name = dw_file_md['filename'] if dw_file_md['filename'] != None else "Upload_from_the_FortiSOAR"
        return file_path, file_name, attachment_data.get('file', {}).get('mimeType')
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def apply_yml_file(config, params):
    try:
        api_instance = generate_token(config, params)
        api_response = api_instance.api_client
        file_path, file_name, file_type = from_cyops_download_file(params.get("file_name"))
        yaml_file = file_path
        utils.create_from_yaml(api_response, yaml_file, verbose=True)
        return {
            'success': 'Successfully deployed'
        }
    except Exception as e:
        raise ConnectorError(e)


def generate_token(config, params):
    configuration = kubernetes.client.Configuration()
    configuration.api_key['authorization'] = config.get('token')
    configuration.host = config.get('host')
    with kubernetes.client.ApiClient(configuration) as api_client:
        api_instance = kubernetes.client.CoreV1Api(api_client)
    return api_instance


def list_namespaced_pod(config, params):
    try:
        namespace = params.get('namespace')
        api_instance = generate_token(config, params)
        api_response = api_instance.list_namespaced_pod(namespace)
        return api_response.to_dict()
    except Exception as e:
        raise ConnectorError(e)


def list_pod_for_all_namespaces(config, params):
    try:
        api_instance = generate_token(config, params)
        api_response = api_instance.list_pod_for_all_namespaces()
        return api_response.to_dict()
    except Exception as e:
        raise ConnectorError(e)


def get_pod_logs(config, params):
    try:
        api_instance = generate_token(config, params)
        name = params.get('pod_name')
        namespace = params.get('namespace')
        return api_instance.read_namespaced_pod_log(name, namespace)
    except Exception as e:
        raise ConnectorError(e)


def delete_namespaced_pod(config, params):
    try:
        api_instance = generate_token(config, params)
        name = params.get('pod_name')
        namespace = params.get('namespace')
        return api_instance.delete_namespaced_pod(name, namespace).to_dict()
    except Exception as e:
        raise ConnectorError(e)


def delete_collection_namespaced_pod(config, params):
    try:
        api_instance = generate_token(config, params)
        namespace = params.get('namespace')
        return api_instance.delete_collection_namespaced_pod(namespace).to_dict()
    except Exception as e:
        raise ConnectorError(e)


def delete_collection_namespaced_secret(config, params):
    try:
        api_instance = generate_token(config, params)
        namespace = params.get('namespace')
        return api_instance.delete_collection_namespaced_secret(namespace).to_dict()
    except Exception as e:
        raise ConnectorError(e)


def delete_namespaced_secret(config, params):
    try:
        api_instance = generate_token(config, params)
        name = params.get('secret_name')
        namespace = params.get('namespace')
        return api_instance.delete_namespaced_secret(name, namespace).to_dict()
    except Exception as e:
        raise ConnectorError(e)


def list_secret_for_all_namespaces(config, params):
    try:
        api_instance = generate_token(config, params)
        return api_instance.list_secret_for_all_namespaces().to_dict()
    except Exception as e:
        raise ConnectorError(e)


def delete_collection_namespaced_config_map(config, params):
    try:
        api_instance = generate_token(config, params)
        namespace = params.get('namespace')
        return api_instance.delete_collection_namespaced_config_map(namespace).to_dict()
    except Exception as e:
        raise ConnectorError(e)


def delete_namespaced_config_map(config, params):
    try:
        api_instance = generate_token(config, params)
        name = params.get('configmap_name')
        namespace = params.get('namespace')
        return api_instance.delete_namespaced_config_map(name, namespace).to_dict()
    except Exception as e:
        raise ConnectorError(e)


def list_config_map_for_all_namespaces(config, params):
    try:
        api_instance = generate_token(config, params)
        return api_instance.list_config_map_for_all_namespaces().to_dict()
    except Exception as e:
        raise ConnectorError(e)


def list_event_for_all_namespaces(config, params):
    try:
        api_instance = generate_token(config, params)
        return api_instance.list_event_for_all_namespaces().to_dict()
    except Exception as e:
        raise ConnectorError(e)


def _check_health(config, connector_info):
    try:
        if generate_token(config, connector_info):
            return True
    except Exception as e:
        logger.error("{0}".format(str(e)))
        raise ConnectorError("{0}".format(str(e)))


operations = {
    'apply_yml_file': apply_yml_file,
    'list_namespaced_pod': list_namespaced_pod,
    'list_pod_for_all_namespaces': list_pod_for_all_namespaces,
    'get_pod_logs': get_pod_logs,
    'delete_namespaced_secret': delete_namespaced_secret,
    'delete_namespaced_pod': delete_namespaced_pod,
    'delete_collection_namespaced_pod': delete_collection_namespaced_pod,
    'delete_collection_namespaced_secret': delete_collection_namespaced_secret,
    'list_secret_for_all_namespaces': list_secret_for_all_namespaces,
    'delete_collection_namespaced_config_map': delete_collection_namespaced_config_map,
    'delete_namespaced_config_map': delete_namespaced_config_map,
    'list_config_map_for_all_namespaces': list_config_map_for_all_namespaces,
    'list_event_for_all_namespaces': list_event_for_all_namespaces
}
