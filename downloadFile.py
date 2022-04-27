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
    #####################
    # create a new dataframe with extracted informations
    df_update_0 = pd.DataFrame(columns=['Title', 'CVE'])

    df_update_0['Title'] = df_vulns['Title.Value']
    df_update_0['CVE'] = df_vulns['CVE']
    #####################

    # list of fields from the normalized json file
    FIELDS = ['Title.Value', 'CVE', 'ProductStatuses']
    df_update = df_vulns[FIELDS]
    ######################

    threats_data = pd.json_normalize(data=vulns, record_path=['Threats'], meta=['CVE', ['Title', 'Value']],
                                     errors='ignore')
    product_data = pd.json_normalize(data=vulns, record_path=['ProductStatuses'], meta=['CVE', ['Title', 'Value']],
                                     errors='ignore')
    cvss_data = pd.json_normalize(data=vulns, record_path=['CVSSScoreSets'], meta=['CVE', ['Title', 'Value']],
                                  errors='ignore')
    revision_data = pd.json_normalize(data=vulns, record_path=['RevisionHistory'], meta=['CVE', ['Title', 'Value']],
                                      errors='ignore')

    with pd.ExcelWriter('output.xlsx') as writer:
        threats_data.to_excel(writer, sheet_name='threats_data', index=False)
        product_data.to_excel(writer, sheet_name='product_data', index=False)
        cvss_data.to_excel(writer, sheet_name='cvss_data', index=False)
        revision_data.to_excel(writer, sheet_name='revision_data', index=False)
    breakpoint()
    # notes = df_vulns.get('Notes')
    # df_notes = pd.json_normalize(notes)



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

# with open(f'{"updates"}_{key}.json', 'w') as outfile:
#     json.dump(json_data, outfile)
# vulns2 = json_data["Vulnerability"]
# vulns4 = json_data.get("Vulnerabilityyy", "")
# vulns3 = json_data["Vulnerabilityyy"]
