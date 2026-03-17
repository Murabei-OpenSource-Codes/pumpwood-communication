"""Module microservice.py.

Class and functions to help communication between PumpWood like systems.
"""
import io
import gzip
import pandas as pd
import simplejson as json
from pandas import ExcelWriter


# Importing abstract classes for Micro Service
from pumpwood_communication.microservice_abc.simple import (
    ABCSimpleBatchMicroservice, ABCSimpleRetriveMicroservice,
    ABCSimpleDeleteMicroservice, ABCSimpleSaveMicroservice,
    ABCSimpleListMicroservice, ABCSimpleDimensionMicroservice,
    ABCSimpleActionMicroservice, ABCSimpleInfoMicroservice)
from pumpwood_communication.microservice_abc.parallel import (
    ABCParallelActionMicroservice, ABCParallelDeleteMicroservice,
    ABCParallelListMicroservice, ABCParallelRetriveMicroservice,
    ABCParallelSaveMicroservice)
from pumpwood_communication.microservice_abc.system import (
    ABCSystemMicroservice, ABCPermissionMicroservice)


class PumpWoodMicroService(ABCPermissionMicroservice,
                           ABCSystemMicroservice,
                           ABCSimpleBatchMicroservice,
                           ABCSimpleRetriveMicroservice,
                           ABCSimpleDeleteMicroservice,
                           ABCSimpleSaveMicroservice,
                           ABCSimpleListMicroservice,
                           ABCSimpleDimensionMicroservice,
                           ABCSimpleActionMicroservice,
                           ABCSimpleInfoMicroservice,
                           ABCParallelActionMicroservice,
                           ABCParallelDeleteMicroservice,
                           ABCParallelListMicroservice,
                           ABCParallelRetriveMicroservice,
                           ABCParallelSaveMicroservice):
    """Class to define an inter-pumpwood MicroService.

    Create an object ot help communication with Pumpwood based backends. It
    manage login and token refresh if necessary.

    It also implements parallel functions that split requests in parallel
    process to reduce processing time.
    """

    ########################
    # Parallel aux functions
    def get_queue_matrix(self, queue_pk: int, auth_header: dict = None,
                         save_as_excel: str = None):
        """Download model queue estimation matrix. In development..."""
        file_content = self.retrieve_file(
            model_class="ModelQueue", pk=queue_pk,
            file_field="model_matrix_file", auth_header=auth_header,
            save_file=False)
        content = gzip.GzipFile(
            fileobj=io.BytesIO(file_content["content"])).read()
        data = json.loads(content.decode('utf-8'))
        columns_info = pd.DataFrame(data["columns_info"])
        model_matrix = pd.DataFrame(data["model_matrix"])

        if save_as_excel is not None:
            writer = ExcelWriter(save_as_excel)
            columns_info.to_excel(writer, 'columns_info', index=False)
            model_matrix.to_excel(writer, 'model_matrix', index=False)
            writer.save()
        else:
            return {
                "columns_info": columns_info,
                "model_matrix": model_matrix}
