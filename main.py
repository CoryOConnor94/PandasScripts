#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
    This script uses the Microsoft API to get monthly security updates of their products,
    as described here:
    https://api.msrc.microsoft.com/cvrf/v2.0/swagger/index .
    Normalizes the json dictionary and brings data to top level table.
    The data is structured according to CVRF (Common Vulnerability Reporting Format) described here:
    http://docs.oasis-open.org/csaf/csaf-cvrf/v1.2/csaf-cvrf-v1.2.html
"""
# ToDo (Cory, Tomasz): What is this script about; what's the intended purpose?
import pandas as pd
import requests
import datetime


def get_date():
    """ Create datetime object containing todays date and returns object
        :return: todays_date
        :rtype: Datetime object
    """
    todays_date = datetime.datetime.now()
    # ToDo (Cory, Tomasz): PEP-8 style guide; variables should be lower case, not CamelCase; i.e. todays_date
    # https://peps.python.org/pep-0008/
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
    # ToDo (Cory, Tomasz): What happens if the HTML response is something other than 200?
    # ToDo (Cory, Tomasz): What happens if an exception is encountered?
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

    # we take only a few vulnerabilities for testing
    vulns = json_data.get('Vulnerability', "")[1:3]
    df_vulns = pd.json_normalize(data=vulns, sep="_")
    df_vulns.drop('Acknowledgments', inplace=True, axis=1)

    # Revision History given per single CVE value
    df_revisionHistory = pd.json_normalize(data=vulns, record_path=['RevisionHistory'], meta=["CVE"], sep="_")
    df_revisionHistory = df_revisionHistory.add_prefix('RevisionHistory_')

    # ToDo (Cory, Tomasz): Take a look at your json_data variable; the key ProductTree contains your product_id to value mapping
    # CVSSScore - for each vulnerability CVE we are given a list of CVSS scores for each ProductID
    df_CVSSScore = pd.json_normalize(data=vulns, record_path=['CVSSScoreSets'], meta=["CVE"], sep="_")
    df_CVSSScore = df_CVSSScore.add_prefix('CVSSScoreSets_')

    # The notes are given for each CVE
    df_notes = pd.json_normalize(data=vulns, record_path=['Notes'], meta=["CVE"], sep="_")
    df_notes = df_notes.add_prefix('Notes_')

    # giving a product status type (affected by the vuln., fixed etc.) for product_ids
    df_ProductStatuses = pd.json_normalize(data=vulns, record_path=['ProductStatuses'], meta=["CVE"], sep="_")
    df_ProductStatuses = df_ProductStatuses.add_prefix('ProductStatuses_')

    df_Threats = pd.json_normalize(data=vulns, record_path=['Threats'], meta=["CVE"], sep="_")
    df_Threats = df_Threats.add_prefix('Threats_')

    # .explode the ProductID column as we want to use it as a key while merging
    df_Remediations = pd.json_normalize(data=vulns, record_path=['Remediations'], meta=["CVE"], sep="_").explode('ProductID')
    df_Remediations = df_Remediations.add_prefix('Remediations_')

    #######################
    # Data Transformations
    #######################
    # CVSSScore
    product_id_list_list = df_CVSSScore.CVSSScoreSets_ProductID.tolist()

    # This is an example of using the string join with a list comprehension
    product_id_list = ["; ".join(prod_id) for prod_id in product_id_list_list]
    # Hyphens in the product_id are just hyphenated ids, not a range (see json_data.ProductTree.FullProductName)
    df_CVSSScore.CVSSScoreSets_ProductID = product_id_list


    # here the error happens probably because of nan values present -> we need to get rid of them earlier or somehow map them to other values
    # Threats
    # replace nans with empty string value in a list
    df_Threats.Threats_ProductID = df_Threats.Threats_ProductID.fillna('').apply(list)

    threats_product_id_list_list = df_Threats.Threats_ProductID.tolist()
    threats_product_id_list = ["; ".join(prod_id) for prod_id in threats_product_id_list_list]

    df_Threats.Threats_ProductID = threats_product_id_list



    #######################
    #       Merging
    #######################
    df_vulns = df_vulns.merge(df_CVSSScore, left_on="CVE", right_on="CVSSScoreSets_CVE", how='left')
    drop_column("CVSSScoreSets_CVE", df_vulns)
    drop_column("CVSSScoreSets", df_vulns)
    print("CVSSScoreSets Done.")

    df_vulns = df_vulns.merge(df_revisionHistory, left_on="CVE", right_on="RevisionHistory_CVE", how='left')
    drop_column("RevisionHistory_CVE", df_vulns)
    drop_column("RevisionHistory", df_vulns)
    print("RevisionHistory Done.")

    # df_vulns = df_vulns.merge(df_notes, left_on="CVE", right_on="Notes_CVE", how='left')
    drop_column("Notes_CVE", df_vulns)
    drop_column("Notes", df_vulns)
    # print("Notes Done.")

    df_vulns = df_vulns.merge(df_ProductStatuses, left_on="CVE", right_on="ProductStatuses_CVE", how='left')
    drop_column("ProductStatuses_CVE", df_vulns)
    drop_column("ProductStatuses", df_vulns)
    print("ProductStatuses Done.")

    # here we merge on ProductIDs as we want to add Threats data to CVSS score for each product
    df_vulns = df_vulns.merge(df_Threats, left_on="CVSSScoreSets_ProductID", right_on="Threats_ProductID", how='left')
    drop_column("Threats_CVE", df_vulns)
    drop_column("Threats", df_vulns)
    print("Threats Done.")
    # FIXME: there is always that one nan value in Threats data as a general information for given CVE - do we need that also?
    # now it is dropped due to the usage of left join

    df_Remediations.drop('Remediations_AffectedFiles', inplace=True, axis=1)
    df_Remediations.drop_duplicates(keep='first')
    # here we merge on ProductIDs as we want only remediations assigned to correct Threat and CVSSscore
    df_vulns = df_vulns.merge(df_Remediations, left_on="Threats_ProductID", right_on="Remediations_ProductID", how='right')
    drop_column("Remediations_CVE", df_vulns)
    drop_column("Remediations", df_vulns)
    print("Remediations Done.")

    # # here we merge on ProductIDs as we want only remediations assigned to correct Threat and CVSSscore
    # df_vulns = df_vulns.merge(df_Remediations, left_on="Threats_ProductID", right_on="Remediations_ProductID", how='inner')
    # drop_column("Remediations_CVE", df_vulns)
    # drop_column("Remediations", df_vulns)
    # print("Remediations Done.")

    print("Done.")

    return df_vulns


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


def product_to_name_mapping(df_vulns, df_windows_items):
    '''
    Is mapping ProductID_Values (names) to df_vulns ProductID and deleting rows that did not match
    :param df_vulns: pd.Dataframe
    :param df_windows_items: pd.Dataframe
    :return: df_vulns: pd.Dataframe
    '''
    df_vulns = pd.merge(df_vulns, df_windows_items, left_on="CVSSScoreSets_ProductID", right_on="ProductTree_ProductID")
    drop_column("ProductTree_ProductID", df_vulns)
    # probably not needed - there should not be any null values when using inner join
    df_vulns.dropna(axis=0, inplace=True, subset=["ProductTree_Value"])

    print("Mapping done.")

    return df_vulns


def save_to_csv(df_msrc):
    '''
    Saving pd.Dataframe as .csv file
    :param df_msrc:
    '''

    print("Writting to file.")
    with open("msrc_security_update_2022_Apr.csv", "w", newline='') as f:
        df_msrc.to_csv(f, index=False)


def main():
    """ Main flow of code; gets todays date, subtract 30 days, format key value,
        download file from last 30 days (last month)
    """
    todays_date = get_date()
    key = get_key(todays_date)
    json_data = get_data(key)
    df_vulns = join_everything_to_top_level(json_data)

    df_windows_items = get_product_tree(json_data)
    df_vulns = product_to_name_mapping(df_vulns, df_windows_items)
    save_to_csv(df_vulns)


if __name__ == "__main__":
    main()
