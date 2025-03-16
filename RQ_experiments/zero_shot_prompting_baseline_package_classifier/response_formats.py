RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "file_classification_schema",
        "schema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "The name of the file being classified"
                },
                "result": {
                    "type": "object",
                    "properties": {
                        "Predicted Classification": {
                            "type": "string",
                            "description": "Prediction of whether the file is Malicious or Benign"
                        },
                        "Malicious Score": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 100,
                            "description": "A score from 0 to 100, where 100 means highly malicious"
                        },
                        "Explanation": {
                            "type": "string",
                            "description": "A brief explanation of why the file is classified this way in two sentences"
                        }
                    },
                    "required": ["Predicted Classification", "Malicious Score", "Explanation"]
                }
            },
            "required": ["filename", "result"],
            "additionalProperties": False
        }
    }
}



OVERALL_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "file_classification_schema",
        "schema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "The name of the file being classified"
                },
                "result": {
                    "type": "object",
                    "properties": {
                        "overall Classification": {
                            "type": "string",
                            "description": "Prediction of whether the file is Malicious or Benign"
                        },
                        "overall Malicious Score": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 100,
                            "description": "A score from 0 to 100, where 100 means highly malicious"
                        },
                        "overall Explanation": {
                            "type": "string",
                            "description": "A brief explanation of why the file is classified this way in two sentences"
                        }
                    },
                    "required": ["Predicted Classification", "Malicious Score", "Explanation"]
                }
            },
            "required": ["filename", "result"],
            "additionalProperties": False
        }
    }
}