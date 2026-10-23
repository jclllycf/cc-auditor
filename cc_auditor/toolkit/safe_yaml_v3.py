"""固定纯 Python PyYAML SafeLoader，限制别名/嵌套/节点；不执行配置中的代码。"""
from cc_auditor._vendor import yaml


class BoundedSafeLoader(yaml.SafeLoader):
    def __init__(self,stream):
        super().__init__(stream);self.node_count=0;self.alias_count=0;self.nesting=0
    def compose_node(self,parent,index):
        self.node_count+=1;self.nesting+=1
        if self.check_event(yaml.AliasEvent):self.alias_count+=1
        if self.node_count>60000 or self.alias_count>128 or self.nesting>60:raise ValueError('yaml_complexity_limit')
        try:return super().compose_node(parent,index)
        finally:self.nesting-=1


def load(text):
    if len(text)>2*1024*1024:raise ValueError('configuration_size_limit')
    try:result=yaml.load(text,Loader=BoundedSafeLoader)
    except yaml.YAMLError:raise ValueError('invalid_safe_yaml') from None
    if type(result) is not dict:raise ValueError('configuration_not_mapping')
    # Reject cyclic collections, which are legal YAML but not useful proxy config.
    visited=set()
    def walk(node,ancestors):
        if isinstance(node,(dict,list)):
            if id(node) in ancestors:raise ValueError('cyclic_yaml')
            if id(node) in visited:return  # Shared alias DAGs must not expand exponentially.
            visited.add(id(node))
            if len(ancestors)>60:raise ValueError('yaml_depth_limit')
            nxt=ancestors|{id(node)}
            for item in (node.values() if isinstance(node,dict) else node):walk(item,nxt)
    walk(result,set());return result
