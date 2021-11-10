import json
import secure_score_utils
import configparser
import os

configParser = configparser.ConfigParser()
configFilePath = os.path.join('secure-score','credentials.config')
configParser.read(configFilePath)

profile_score = secure_score_utils.generate_score_profile_dataframe()

workspace_id = configParser.get('Log_Analytics', 'workspace_id')
primary_key = configParser.get('Log_Analytics', 'primary_key')
body = profile_score
log_type = configParser.get('Log_Analytics', 'log_type')

n = 1000  # chunk row size
list_df = [profile_score[i:i+n] for i in range(0, profile_score.shape[0], n)]
for df in list_df:
    secure_score_utils.post_data(workspace_id, primary_key, json.dumps(df.to_dict("records")), log_type)