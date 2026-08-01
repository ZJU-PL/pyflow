from flask import Flask, request, jsonify
import json
import yaml
import datetime
from uuid import uuid4
from enum import Enum
from typing import Dict, List, Any

app = Flask(__name__)

class StepType(Enum):
    ACTION = "action"
    CONDITION = "condition"

class ActionType(Enum):
    JSON_LOAD = "json_load"
    JSON_DUMP = "json_dump"
    YAML_DUMP = "yaml_dump"
    STR_UPPER = "str_upper"
    STR_LOWER = "str_lower"
    LIST_MAP = "list_map"

class ConditionOperator(Enum):
    EQUAL = "=="
    NOT_EQUAL = "!="
    GREATER = ">"
    LESS = "<"
    GREATER_EQUAL = ">="
    LESS_EQUAL = "<="
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"

class WorkflowEngine:
    def __init__(self):
        self.workflows = {}
        self.safe_functions = {
            'uuid4': uuid4,
            'datetime': datetime.datetime
        }
    
    def register_workflow(self, name: str, steps: List[Dict]) -> None:
        """Register a workflow with validated steps"""
        validated_steps = []
        for step in steps:
            if not isinstance(step, dict):
                raise ValueError("Each step must be a dictionary")
            
            step_type = StepType(step.get('type', 'action'))
            validated_step = {'type': step_type.value}
            
            if step_type == StepType.ACTION:
                action = ActionType(step['action'])
                validated_step['action'] = action.value
                validated_step['params'] = step.get('params', {})
            elif step_type == StepType.CONDITION:
                operator = ConditionOperator(step['operator'])
                validated_step['field'] = step['field']
                validated_step['operator'] = operator.value
                validated_step['value'] = step['value']
            
            validated_step['name'] = step.get('name', 'unnamed')
            validated_steps.append(validated_step)
        
        self.workflows[name] = validated_steps
    
    def _execute_action(self, action: str, params: Dict, context: Dict) -> Dict:
        """Execute a safe predefined action"""
        try:
            action_type = ActionType(action)
            
            if action_type == ActionType.JSON_LOAD:
                context[params['output']] = json.loads(context[params['input']])
            elif action_type == ActionType.JSON_DUMP:
                context[params['output']] = json.dumps(context[params['input']])
            elif action_type == ActionType.YAML_DUMP:
                context[params['output']] = yaml.dump(context[params['input']])
            elif action_type == ActionType.STR_UPPER:
                context[params['output']] = str(context[params['input']]).upper()
            elif action_type == ActionType.STR_LOWER:
                context[params['output']] = str(context[params['input']]).lower()
            elif action_type == ActionType.LIST_MAP:
                func = ActionType(params['func'])
                context[params['output']] = [
                    str(item).upper() if func == ActionType.STR_UPPER else str(item).lower()
                    for item in context[params['input']]
                ]
            
            return {'status': 'success'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def _evaluate_condition(self, field: str, operator: str, value: Any, context: Dict) -> Dict:
        """Evaluate a safe condition"""
        try:
            field_value = context.get(field)
            op = ConditionOperator(operator)
            
            if op == ConditionOperator.EQUAL:
                result = field_value == value
            elif op == ConditionOperator.NOT_EQUAL:
                result = field_value != value
            elif op == ConditionOperator.GREATER:
                result = field_value > value
            elif op == ConditionOperator.LESS:
                result = field_value < value
            elif op == ConditionOperator.GREATER_EQUAL:
                result = field_value >= value
            elif op == ConditionOperator.LESS_EQUAL:
                result = field_value <= value
            elif op == ConditionOperator.CONTAINS:
                result = str(value) in str(field_value)
            elif op == ConditionOperator.STARTS_WITH:
                result = str(field_value).startswith(str(value))
            elif op == ConditionOperator.ENDS_WITH:
                result = str(field_value).endswith(str(value))
            
            return {'status': 'success', 'result': result}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def execute_workflow(self, name: str, initial_context: Dict = None) -> Dict:
        """Execute a registered workflow"""
        if name not in self.workflows:
            return {'error': f'Workflow {name} not found'}
        
        context = initial_context or {}
        execution_log = []
        
        for step in self.workflows[name]:
            step_type = StepType(step['type'])
            step_result = None
            
            if step_type == StepType.ACTION:
                step_result = self._execute_action(
                    step['action'],
                    step.get('params', {}),
                    context
                )
            elif step_type == StepType.CONDITION:
                step_result = self._evaluate_condition(
                    step['field'],
                    step['operator'],
                    step['value'],
                    context
                )
            
            execution_log.append({
                'step': step['name'],
                'result': step_result
            })
            
            if step_result['status'] == 'error':
                break
        
        return {
            'workflow': name,
            'status': 'completed' if execution_log[-1]['status'] == 'success' else 'failed',
            'context': context,
            'execution_log': execution_log
        }

workflow_engine = WorkflowEngine()

# Register sample workflows using safe format
workflow_engine.register_workflow('data_processing', [
    {
        'name': 'load_data',
        'type': 'action',
        'action': 'json_load',
        'params': {'input': 'input_data', 'output': 'raw_data'}
    },
    {
        'name': 'transform',
        'type': 'action',
        'action': 'list_map',
        'params': {
            'input': 'raw_data',
            'output': 'processed',
            'func': 'str_upper'
        }
    },
    {
        'name': 'save',
        'type': 'action',
        'action': 'yaml_dump',
        'params': {'input': 'processed', 'output': 'output'}
    }
])

@app.route('/api/workflows/execute', methods=['POST'])
def execute_workflow():
    data = request.get_json()
    if not data or 'workflow' not in data:
        return jsonify({'error': 'Workflow name required'}), 400
    
    try:
        result = workflow_engine.execute_workflow(
            data['workflow'],
            data.get('context', {})
        )
        return jsonify(result)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        return jsonify({'error': 'Internal server error'}), 500

# Removed the vulnerable /api/workflows/custom endpoint
# Removed the vulnerable /api/expressions/evaluate endpoint

if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production