"""Module for ETL trigger calls on Pumpwood microservices."""
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
                            auth_header: dict | None = None
                            ) -> bool | None:
        """Trigger an ETL process via the ETLTrigger action.

        If ``pumpwood-etl-app`` is not registered at Kong, no request is
        sent and the method returns ``None``.

        Args:
            model_class (str):
                Model class name that originated the trigger.
            trigger_type (Literal):
                Kind of event: ``create``, ``update``, ``delete``,
                ``action``, or ``process_finish``.
            object_id (int | None):
                Primary key of the affected object, when applicable.
            action_name (str | None):
                Name of the action when ``trigger_type`` is ``action``.
            parameters (dict | None):
                Extra parameters forwarded to matching ETL triggers.
            process_name (str | None):
                Optional ETL process name to restrict matching triggers.
            send_to_rabbitmq (bool):
                If True, enqueue work on RabbitMQ. Defaults to True.
            auth_header (dict | None):
                Auth header to substitute the microservice original at
                the request (user impersonation).

        Returns:
            bool | None:
                The ``result`` field from ``process_matching_triggers``
                when the ETL app is registered; ``None`` when it is not.

        Raises:
            PumpWoodException:
                If ``process_matching_triggers`` is not available on
                ``ETLTrigger``.
            PumpWoodActionArgsException:
                If action arguments are invalid for
                ``process_matching_triggers``.
            PumpWoodObjectDoesNotExist:
                If a requested object referenced by the action is not
                found.
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
