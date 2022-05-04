import pandas as pd
import requests
import datetime


def get_date():
    """ Create datetime object containing todays date and returns object
        :param: None
        :type:
        :return: todaysDate
        :rtype: Datetime object
    """
    todaysDate = datetime.datetime.now()

    return todaysDate


def get_key(td):
    """ Receives todays date, subtract 30 days, format key from result
        :param: td
        :type: datetime object
        :return: key
        :rtype: string
    """
    delta = datetime.timedelta(days=30)
    newdate = td - delta
    key = newdate.strftime("%Y-%b")

    return key


def get_data(key):
    """ Downloads json file using key
        :param: key
        :type: string
        :return: None
        :rtype: N/A
    """
    url = "https://api.msrc.microsoft.com/cvrf/v2.0/document/" + key
    headers = {'Accept': 'application/json'}
    response = requests.get(url, headers=headers)
    json_data = response.json()

    return json_data


def parse_data(json_data):
    """ Normalize json data, access required data
            :param: json_data
            :type:
            :return: none
            :rtype: N/A
    """
    vulns = json_data.get('Vulnerability')
    df_vulns = pd.json_normalize(vulns)
    
    df_revisionHistory = pd.json_normalize(data=vulns, record_path=['RevisionHistory'])
    df_revisionHistory.rename(columns = {'Number':'RevisionHistory.Number', 'Date':'RevisionHistory.Date','Description.Value':'RevisionHistory.Description'}, inplace = True)
    df_vulns = df_vulns.join(df_revisionHistory)
    pd.set_option('display.max_columns', 40)
    df_vulns.drop('RevisionHistory', inplace=True, axis=1)
    
    df_CVSSScore = pd.json_normalize(data=vulns, record_path=['CVSSScoreSets'])
    df_CVSSScore.rename(columns = {'BaseScore':'cvssScore.BaseScore', 'TemporalScore':'cvssScore.TemporalScore','Vector':'cvssScore.Vector','ProductID':'cvssScore.ProductID'}, inplace = True)
    df_vulns = df_vulns.join(df_CVSSScore)
    df_vulns.drop('CVSSScoreSets', inplace=True, axis=1)
    
    df_notes = pd.json_normalize(data=vulns, record_path=['Notes'])
    df_notes.rename(columns = {'Ordinal':'Notes.Ordinal', 'Type':'Notes.Type','Title':'Notes.Title','Value':'Notes.Value'}, inplace = True)
    df_vulns = df_vulns.join(df_notes)
    df_vulns.drop('Notes', inplace=True, axis=1)
    
    df_ProductStatuses = pd.json_normalize(data=vulns, record_path=['ProductStatuses'])
    df_ProductStatuses.rename(columns = {'Type':'ProductStatuses.Type','ProductID':'ProductStatuses.ProductID'}, inplace = True)
    df_vulns = df_vulns.join(df_ProductStatuses)
    df_vulns.drop('ProductStatuses', inplace=True, axis=1)
    
    df_Threats = pd.json_normalize(data=vulns, record_path=['Threats'])
    df_Threats.rename(columns = {'ProductID':'Threats.ProductID', 'Type':'Threats.Type', 'Description.Value':'Threats.DescriptionValue','DateSpecified':'Threats.DateSpecified'}, inplace = True)
    df_vulns = df_vulns.join(df_Threats)
    df_vulns.drop('Threats', inplace=True, axis=1)
    
    df_Remediations = pd.json_normalize(data=vulns, record_path=['Remediations'])
    df_Remediations.rename(columns = {'URL':'Remediations.URL', 'Supercedence':'Remediations.Supercedence', 'ProductID':'Remediations.ProductID','Type':'Remediations.Type','Description.Value':'Remediations.DescriptionValue','DateSpecified':'Remediations.DateSpecified','AffectedFiles':'Remediations.AffectedFiles','SubType':'Remediations.SubType','FixedBuild':'Remediations.FixedBuild','RestartRequired.Value':'Remediations.RestartRequired'}, inplace = True)
    df_vulns = df_vulns.join(df_Remediations)
    df_vulns.drop('Remediations', inplace=True, axis=1)
    
    df_vulns.drop('Acknowledgments', inplace=True, axis=1)
    
    
def main():
    """ Main flow of code; gets todays date, subtract 30 days, format key value,
        download file from last 30 days
    """
    todaysDate = get_date()
    key = get_key(todaysDate)
    json_data = get_data(key)
    parse_data(json_data)


if __name__ == "__main__":
    main()
