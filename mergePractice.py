import pandas as pd
import requests
import datetime


def get_date():
    """ Create datetime object containing todays date and returns object
        :return: todays_date
        :rtype: Datetime object
    """
    todays_date = datetime.datetime.now()
    return todays_date


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
    """ Downloads json file using key value representing the month in the form: 'yyyy-mmm' e.g. '2022-Apr'.
        Function will raise exception and exit if any HTTPError or RequestException is encountered.
        :param: key
        :type: string
        :return: json_data
        :rtype: JSON object
    """
    url = "https://api.msrc.microsoft.com/cvrf/v2.0/document/" + key
    headers = {'Accept': 'application/json'}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        raise SystemExit(err)
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)

    json_data = response.json()

    return json_data


def join_everything_to_top_level(json_data):
    """ Normalize json data, access required data, Join data to top level DataFrame
    :param: json_data
    :type: Dictionary
    :return: df_vulns
    :rtype: DataFrame
    """

    vulns = json_data.get('Vulnerability', "")
    df_vulns = pd.json_normalize(data=vulns, sep="_")
    df_vulns.drop('Acknowledgments', inplace=True, axis=1)

    # Revision History given per single CVE value
    df_revisionHistory = pd.json_normalize(data=vulns, record_path=['RevisionHistory'], meta=["CVE"], sep="_")

    # CVSSScore - for each vulnerability CVE we are given a list of CVSS scores for each ProductID
    df_CVSSScore = pd.json_normalize(data=vulns, record_path=['CVSSScoreSets'], meta=["CVE"], sep="_")

    df_notes = pd.json_normalize(data=vulns, record_path=['Notes'], meta=["CVE"], sep="_")

    # giving a product status type (affected by the vuln., fixed etc.) for product_ids
    df_ProductStatuses = pd.json_normalize(data=vulns, record_path=['ProductStatuses'], meta=["CVE"], sep="_")

    df_Threats = pd.json_normalize(data=vulns, record_path=['Threats'], meta=["CVE"], sep="_")

    # .explode the ProductID column as we want to use it as a key while merging
    df_Remediations = pd.json_normalize(data=vulns, record_path=['Remediations'], meta=["CVE"], sep="_").explode('ProductID')
    print(9)
    frames = [df_Remediations, df_Threats]
    df_Remediations.drop('AffectedFiles', inplace=True, axis=1)
    #merged_frame = df_Remediations.merge(df_Threats)
    joined_frame = df_Remediations.join(df_Threats)
    concat_frame = pd.concat(frames)
    print(1)
def get_product_tree(json_data) -> pd.DataFrame:
    '''
    Gets ProductTree structure from the json data. ProductTree contains ProductID to Product Name mapping.
    Filters for only Windows related products.
    :param json_data:
    :type: Dictionary
    :return: df_windows_items
    :rtype: pd.DataFrame
    '''
    product_tree = json_data.get("ProductTree", "")
    df_product_tree = pd.json_normalize(data=product_tree, record_path=["Branch", "Items"], sep='_').explode('Items')

    df_windows_items = df_product_tree
    df_windows_items = df_windows_items[df_windows_items['Name'] == 'Windows']
    df_windows_items = pd.json_normalize(data=df_windows_items["Items"])
    df_windows_items = df_windows_items.add_prefix('ProductTree_')

    return df_windows_items


def drop_column(column_name, df_vulns):
    """ Drop unwanted columns from DataFrame
                :param: df_vulns
                :type: DataFrame
                :return: df_vulns
                :rtype: DataFrame
        """
    try:
        df_vulns.drop(f'{column_name}', inplace=True, axis=1)
    except Exception as e:
        print(f"Exception for dropping of {column_name} column:")
        print(e)

def main():
    """ Main flow of code; gets todays date, subtract 30 days, format key value,
        download file from last 30 days (last month)
    """
    todays_date = get_date()
    key = get_key(todays_date)
    json_data = get_data(key)
    join_everything_to_top_level(json_data)

    df_windows_items = get_product_tree(json_data)



if __name__ == "__main__":
    main()