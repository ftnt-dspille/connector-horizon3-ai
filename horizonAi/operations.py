import enum

from connectors.core.connector import get_logger, ConnectorError

from .horizon_api_auth import HorizonAPI

logger = get_logger('horizon-ai')


class SortOrder(enum.Enum):
    ASC = "ASC"
    DESC = "DESC"


def build_page_input(params):
    """
    Build the PageInput object from provided parameters
    """

    def safe_int(value, default):
        """
        Safely convert a value to an integer, falling back to a default if conversion fails.
        """
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    # Safely enforce integers for page_num and page_size
    page_input = {
        "page_num": safe_int(params.get('page_num'), 1),
        "page_size": safe_int(params.get('page_size'), 50)
    }

    # Add ordering if specified
    if params.get('order_by'):
        page_input["order_by"] = params['order_by']
        page_input["sort_order"] = params.get('sort_order', 'ASC')

    # Add text search if specified
    if params.get('text_search'):
        page_input["text_search"] = params['text_search']

    # Add filters if specified
    filters = []

    # Handle date range filters
    if params.get('date_from') or params.get('date_to'):
        field_name = params.get('date_field', 'launched_at')
        if params.get('date_from'):
            filters.append({
                "field_name": field_name,
                "greater_than": params['date_from']
            })
        if params.get('date_to'):
            filters.append({
                "field_name": field_name,
                "less_than": params['date_to']
            })

    # Handle state filter
    if params.get('state'):
        filters.append({
            "field_name": "state",
            "values": params['state']
        })

    # Handle client name filter
    if params.get('client_name'):
        filters.append({
            "field_name": "client_name",
            "values": params['client_name']
        })

    # Add the filters if any were created
    if filters:
        page_input["filter_by_inputs"] = filters

    return page_input


def get_pentests(config, params):
    try:
        horizon = HorizonAPI(config)
        # Base fields that are always included
        base_fields = """
            op_id
            op_type
            name
            state
            user_name
            client_name
            min_scope
            max_scope
            exclude_scope
            scheduled_at
            launched_at
            completed_at
            canceled_at
            etl_completed_at
            duration_s
            impacts_count
            impact_paths_count
            attack_paths_count
            phished_impact_paths_count
            phished_attack_paths_count
            weakness_types_count
            weaknesses_count
            hosts_count
            out_of_scope_hosts_count
            external_domains_count
            services_count
            credentials_count
            users_count
            cred_access_count
            data_stores_count
            websites_count
            data_resources_count
            nodezero_script_url
            nodezero_ip
        """

        # Optional attack paths fields
        attack_paths_fields = """
            attack_paths_page {
                page_info {
                    page_size
                    end_cursor
                }
                attack_paths {
                    uuid
                    impact_type
                    impact_title
                    impact_description
                    name
                    attack_path_title
                    base_score
                    score
                    severity
                    context_score_description_md
                    op_id
                    weakness_refs
                    credential_refs
                    host_refs
                    time_to_finding_hms
                    time_to_finding_s
                    created_at
                    target_entity_text
                    affected_asset_text
                    ip
                    host_name
                    host_text
                }
            }
        """ if params.get('include_attack_paths') else ""

        # Optional weaknesses fields
        weaknesses_fields = """
            weaknesses_page {
                page_info {
                    page_size
                    end_cursor
                }
                weaknesses {
                    uuid
                    created_at
                    vuln_id
                    vuln_aliases
                    vuln_category
                    vuln_name
                    vuln_short_name
                    vuln_cisa_kev
                    vuln_known_ransomware_campaign_use
                    op_id
                    ip
                    has_proof
                    proof_failure_code
                    proof_failure_reason
                    score
                    severity
                    base_score
                    base_severity
                    context_score
                    context_severity
                    context_score_description_md
                    context_score_description
                    time_to_finding_hms
                    time_to_finding_s
                    affected_asset_text
                    downstream_impact_types
                    downstream_impact_types_and_counts
                    impact_paths_count
                    attack_paths_count
                    diff_status
                    mitre_mappings {
                        mitre_tactic_id
                        mitre_technique_id
                        mitre_subtechnique_id
                    }
                }
            }
        """ if params.get('include_weaknesses') else ""

        query = f"""
        query pentests_page($page_input: PageInput) {{
            pentests_page(page_input: $page_input) {{
                pentests {{
                    {base_fields}
                    {attack_paths_fields}
                    {weaknesses_fields}
                }}
                page_info {{
                    page_size
                    end_cursor
                }}
            }}
        }}
        """

        variables = {
            "page_input": build_page_input(params)
        }

        return horizon.make_request(query, variables)
    except Exception as e:
        logger.error(f"Error getting pentests: {str(e)}")
        raise ConnectorError(str(e))


def get_attack_paths(config, params):
    try:
        horizon = HorizonAPI(config)
        op_id = params.get('op_id')
        if not op_id:
            raise ConnectorError("op_id is required")

        query = """
            query attack_paths_page($input: OpInput!, $page_input: PageInput) {
              attack_paths_page(input: $input, page_input: $page_input) {
                attack_paths {
                    uuid
                    impact_type
                    impact_title
                    impact_description
                    name
                    attack_path_title
                    base_score
                    score
                    severity
                    context_score_description_md
                    op_id
                    weakness_refs
                    credential_refs
                    host_refs
                    time_to_finding_hms
                    time_to_finding_s
                    created_at
                    target_entity_text
                    affected_asset_text
                    ip
                    host_name
                    host_text
                }
                page_info {
                    page_size
                    end_cursor
                }
            }
        }
        """

        variables = {
            "input": {"op_id": op_id},
            "page_input": build_page_input(params)
        }

        return horizon.make_request(query, variables)
    except Exception as e:
        logger.error(f"Error getting attack paths: {str(e)}")
        raise ConnectorError(str(e))


def get_weaknesses(config, params):
    try:
        horizon = HorizonAPI(config)
        op_id = params.get('op_id')
        if not op_id:
            raise ConnectorError("op_id is required")

        query = """
        query weaknesses_page($input: OpInput!, $page_input: PageInput) {
            weaknesses_page(input: $input, page_input: $page_input) {
                weaknesses {
                    uuid
                    created_at
                    vuln_id
                    vuln_aliases
                    vuln_category
                    vuln_name
                    vuln_short_name
                    vuln_cisa_kev
                    vuln_known_ransomware_campaign_use
                    op_id
                    ip
                    has_proof
                    proof_failure_code
                    proof_failure_reason
                    score
                    severity
                    base_score
                    base_severity
                    context_score
                    context_severity
                    context_score_description_md
                    context_score_description
                    time_to_finding_hms
                    time_to_finding_s
                    affected_asset_text
                    downstream_impact_types
                    downstream_impact_types_and_counts
                    impact_paths_count
                    attack_paths_count
                    diff_status
                    mitre_mappings {
                        mitre_tactic_id
                        mitre_technique_id
                        mitre_subtechnique_id
                    }
                }
                page_info {
                    page_size
                    end_cursor
                }
            }
        }
        """

        variables = {
            "input": {"op_id": op_id},
            "page_input": build_page_input(params)
        }

        return horizon.make_request(query, variables)
    except Exception as e:
        logger.error(f"Error getting weaknesses: {str(e)}")
        raise ConnectorError(str(e))


def health_check(config):
    try:
        horizon = HorizonAPI(config)
        return horizon.check_health()
    except Exception as err:
        logger.error(f"Health check error: {str(err)}")
        raise ConnectorError(str(err))


operations = {
    'get_pentests': get_pentests,
    'get_attack_paths': get_attack_paths,
    'get_weaknesses': get_weaknesses,
    'check_health': health_check
}
