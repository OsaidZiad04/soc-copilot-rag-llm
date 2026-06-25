from .BaseController import BaseController
from .ProjectController import ProjectController
from fastapi import UploadFile
from models import ResponseSignal, ProcessingEnum
import re
import os


class DataController(BaseController):

    def __init__(self):
        super().__init__()

    def validate_uploaded_file(self, file: UploadFile):

        file_ext = os.path.splitext(file.filename or "")[-1].lower()
        is_supported_log_file = file_ext == ProcessingEnum.LOG.value
        is_supported_text_file = file_ext in {ProcessingEnum.TXT.value, ProcessingEnum.PDF.value, ProcessingEnum.LOG.value}

        if file.content_type not in self.app_settings.FILE_ALLOWED_TYPES and not is_supported_log_file and not is_supported_text_file:
            return False, ResponseSignal.FILE_TYPE_NOT_SUPPORTED.value

        file_size = getattr(file, "size", None)
        if file_size is not None and file_size > self.app_settings.FILE_MAX_SIZE:
            return False, ResponseSignal.FILE_SIZE_EXCEEDED.value

        return True, ResponseSignal.FILE_VALIDATED_SUCCESS.value

    def generate_unique_filepath(self, orig_file_name: str, project_id: str):

        random_key = self.generate_random_string()
        project_path = ProjectController().get_project_path(project_id=project_id)

        cleaned_file_name = self.get_clean_file_name(
            orig_file_name=orig_file_name
        )

        new_file_path = os.path.join(
            project_path,
            random_key + "_" + cleaned_file_name
        )

        while os.path.exists(new_file_path):
            random_key = self.generate_random_string()
            new_file_path = os.path.join(
                project_path,
                random_key + "_" + cleaned_file_name
            )

        return new_file_path, random_key + "_" + cleaned_file_name

    def get_clean_file_name(self, orig_file_name: str):

        # remove any special characters, except underscore and .
        cleaned_file_name = re.sub(r'[^\w.]', '', orig_file_name.strip())

        # replace spaces with underscore
        cleaned_file_name = cleaned_file_name.replace(" ", "_")

        return cleaned_file_name
