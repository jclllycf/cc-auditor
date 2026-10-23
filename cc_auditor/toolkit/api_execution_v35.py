"""API 执行视点分类。只消费获准元数据/枚举，不读凭据，不按品牌猜模型。"""
MODES = ('unknown', 'local_sdk_direct', 'local_agent_direct', 'agent_platform_cloud',
         'third_party_gateway', 'platform_builtin_model')


def classify(report):
    raw = report.get('user_declarations') or {}
    context = (report.get('program_context_v33') or {}).get('api') or {}
    selected = 'api' in raw.get('surfaces', ['desktop', 'web'])
    mode = raw.get('api_execution_mode')
    origin = 'native_user_declaration' if mode in MODES and mode != 'unknown' else 'not_identified'
    mode = mode if mode in MODES else 'unknown'
    # Only installed SDK metadata AND an actual host binding establish a candidate.
    # An application brand or SDK declaration alone cannot establish request origin.
    if mode == 'unknown' and context.get('sdk_installed') is True and context.get('host_bound') is True:
        mode = 'local_sdk_direct'; origin = 'approved_sdk_metadata_and_host_binding'
    host = context.get('host_kind') or raw.get('api_host', 'unknown')
    remote_host = host in ('remote', 'wsl', 'container')
    local = mode in ('local_sdk_direct', 'local_agent_direct') and (not remote_host or
            host in ('wsl', 'container') and (context.get('preuse_host_bound') is True or context.get('host_bound') is True))
    applicable = selected and mode != 'platform_builtin_model'
    actual = (host if local and remote_host else 'local_windows' if local else host if mode == 'local_sdk_direct' and remote_host else
              'platform_cloud' if mode == 'agent_platform_cloud' else
              'gateway_upstream' if mode == 'third_party_gateway' else
              'no_claude_path' if mode == 'platform_builtin_model' else 'unknown')
    return {'execution_mode': mode, 'classification_source': origin, 'selected': selected,
            'applicable': applicable, 'actual_request_origin': actual,
            'local_path_candidate': local, 'host_scope': host,
            'egress_owner': actual, 'remote_api_path_observed': False,
            'anthropic_path_confirmed': False,
            'boundary': ('本次未选择 API' if not selected else '所选平台内置非 Claude 模型；本次没有 Claude API 意图' if not applicable else
                         '本机中立探针仅验证系统基础；未运行 Agent、SDK 或模型请求' if local else
                         '真实 API 请求在第三方云端或网关；本机结果仅说明客户端接入基础' if mode in ('agent_platform_cloud', 'third_party_gateway') else
                         '实际请求执行环境尚未可靠识别；本机结果不能代替远端链路')}
