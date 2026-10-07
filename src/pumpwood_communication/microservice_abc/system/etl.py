"""Pumpwood internal and auxiliary associated requests."""
from abc import ABC
from typing import Literal
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)


class ABCETLMicroservice(ABC, PumpWoodMicroServiceBase):
    """ABC class to define ETL associated requests.

    ETL associated request involve trigger an ETL process.
    """

    def trigger_etl_process(self, model_class: str,
                            trigger_type: Literal[
                                    'create', 'update', 'delete', 'action',
                                    'process_finish'],
                            object_id: int | None = None,
                            action_name: str | None = None,
                            parameters: dict | None = None,
                            process_name: str | None = None,
                            send_to_rabbitmq: bool = True,
                            auth_header: dict = None) -> bool:
        """Trigger an ETL process.

        This request will trigger an ETL process.
        """
        is_etl_app_registered = self.is_microservice_registered(
            microservice="pumpwood-etl-app",
            auth_header=auth_header)
        if not is_etl_app_registered:
            return None

        # Trigger the ETL process
        action_result = self.execute_action(
            model_class="ETLTrigger",
            action="process_matching_triggers",
            parameters={
                'model_class': model_class,
                'trigger_type': trigger_type,
                'object_id': object_id,
                'action_name': action_name,
                'parameters': parameters,
                'process_name': process_name,
                'send_to_rabbitmq': send_to_rabbitmq},
            auth_header=auth_header)['result']
        return action_result