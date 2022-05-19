#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
""" Script downloads the latest Microsoft security updates released in the last 30 days
    Normalizes the json dictionary and brings data to top level"""
# ToDo (Cory, Tomasz): What is this script about; what's the intended purpose?
import pandas as pd
import requests
import datetime


def get_date():
    """ Create datetime object containing todays date and returns object
        :return: todaysDate
        :rtype: Datetime object
    """
    # ToDo (Cory, Tomasz): If there are no params, go ahead and remove param/type
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
    new_date = td - delta
    key = new_date.strftime("%Y-%b")

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
    try:
        response = requests.get(url, headers=headers)
        # ToDo (Cory, Tomasz): What happens if the HTML response is something other than 200?
        # ToDo (Cory, Tomasz): What happens if an exception is encountered?
        json_data = response.json()

        return json_data

    except Exception as e:
        print(e)


def join_everything_to_top_level(json_data):
    """ Normalize json data, access required data, Join data to top level DataFrame
    :param: json_data
    :type: Dictionary
    :return: df_vulns
    :rtype: DataFrame
    """

    vulns = json_data.get('Vulnerability', "")
    tree = json_data.get('ProductTree').get('Branch')

    df_vulns = pd.json_normalize(data=vulns, sep="_")
    df_branch = pd.json_normalize(tree,'Items')

    df_branch2 = df_branch.explode('Items')

    productIDs = df_branch2['Items']

    df_productIDs = pd.json_normalize(productIDs)

    print(0)

    df_revisionHistory = pd.json_normalize(data=vulns, record_path=['RevisionHistory'], sep="_")
    df_revisionHistory = df_revisionHistory.add_prefix('RevisionHistory_')

    # ToDo (Cory, Tomasz): Take a look at your json_data variable; the key ProductTree contains your product_id to value mapping
    df_CVSSScore = pd.json_normalize(data=vulns, record_path=['CVSSScoreSets'], sep="_")
    df_CVSSScore = df_CVSSScore.add_prefix('CVSSScore_')

    product_id_list_list = df_CVSSScore.CVSSScore_ProductID.tolist()

    # This is an example of using the string join with a list comprehension
    product_id_list = ["; ".join(prod_id) for prod_id in product_id_list_list]

    # Hyphens in the product_id are just hyphenated ids, not a range (see json_data.ProductTree.FullProductName)
    df_CVSSScore.CVSSScore_ProductID = product_id_list

    df_notes = pd.json_normalize(data=vulns, record_path=['Notes'], sep="_")
    df_notes = df_notes.add_prefix('Notes_')

    df_ProductStatuses = pd.json_normalize(data=vulns, record_path=['ProductStatuses'], sep="_")
    df_ProductStatuses = df_ProductStatuses.add_prefix('ProductStatuses_')

    df_Threats = pd.json_normalize(data=vulns, record_path=['Threats'], sep="_")
    df_Threats = df_Threats.add_prefix('Threats_')

    df_Remediations = pd.json_normalize(data=vulns, record_path=['Remediations'], sep="_")
    df_Remediations = df_Remediations.add_prefix('Remediations_')

    df_vulns = df_vulns.join(df_CVSSScore).join(df_revisionHistory).join(df_notes).join(df_ProductStatuses).join(df_Threats).join(df_Remediations).join(df_productIDs)

    return df_vulns


def drop_columns(df_vulns):
    """ Drop unwanted columns from DataFrame
                :param: df_vulns
                :type: DataFrame
                :return: df_vulns
                :rtype: DataFrame
        """

    df_vulns.drop('RevisionHistory', inplace=True, axis=1)
    df_vulns.drop('CVSSScoreSets', inplace=True, axis=1)
    df_vulns.drop('Notes', inplace=True, axis=1)
    df_vulns.drop('ProductStatuses', inplace=True, axis=1)
    df_vulns.drop('Threats', inplace=True, axis=1)
    df_vulns.drop('Remediations', inplace=True, axis=1)
    df_vulns.drop('Acknowledgments', inplace=True, axis=1)

    # no return required, make sure when you call this (what will now be a method)
    # that you are not assigning to a variable - which you are not doing
    return df_vulns


def main():
    """ Main flow of code; gets todays date, subtract 30 days, format key value,
        download file from last 30 days
    """
    todays_date = get_date()
    key = get_key(todays_date)
    json_data = get_data(key)
    df_vulns = join_everything_to_top_level(json_data)
    drop_columns(df_vulns)
    print(1)

if __name__ == "__main__":
    main()
