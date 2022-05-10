#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
""" DOCSTRING """
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


def get_vulnerability_data_from_json(json_data):
    """ Normalize json data about vulnerabilities
            :param: json_data
            :type:
            :return: none
            :rtype: N/A
    """
    vulns = json_data.get('Vulnerability')
    df_vulns = pd.json_normalize(data=vulns, sep="_")

    return df_vulns


def join_everything_to_top_level(json_data):
    """ Normalize json data, access required data
            :param: json_data
            :type:
            :return: none
            :rtype: N/A
    """

    vulns = json_data.get('Vulnerability', "")
    df_vulns = pd.json_normalize(data=vulns, sep="_")

    df_revisionHistory = pd.json_normalize(data=vulns, record_path=['RevisionHistory'], sep="_")
    df_revisionHistory = df_revisionHistory.add_prefix('RevisionHistory_')
    df_vulns = df_vulns.join(df_revisionHistory)
    df_vulns.drop('RevisionHistory', inplace=True, axis=1)

    df_CVSSScore = pd.json_normalize(data=vulns, record_path=['CVSSScoreSets'], sep="_")
    df_CVSSScore = df_CVSSScore.add_prefix('CVSSScore_')
    df_vulns = df_vulns.join(df_CVSSScore)
    df_vulns.drop('CVSSScoreSets', inplace=True, axis=1)

    df_notes = pd.json_normalize(data=vulns, record_path=['Notes'], sep="_")
    df_notes = df_notes.add_prefix('Notes_')
    df_vulns = df_vulns.join(df_notes)
    df_vulns.drop('Notes', inplace=True, axis=1)

    df_ProductStatuses = pd.json_normalize(data=vulns, record_path=['ProductStatuses'], sep="_")
    df_ProductStatuses = df_ProductStatuses.add_prefix('ProductStatuses_')
    df_vulns = df_vulns.join(df_ProductStatuses)
    df_vulns.drop('ProductStatuses', inplace=True, axis=1)

    df_Threats = pd.json_normalize(data=vulns, record_path=['Threats'], sep="_")
    df_Threats = df_Threats.add_prefix('Threats_')
    df_vulns = df_vulns.join(df_Threats)
    df_vulns.drop('Threats', inplace=True, axis=1)

    df_Remediations = pd.json_normalize(data=vulns, record_path=['Remediations'], sep="_")
    df_Remediations = df_Remediations.add_prefix('Remediations_')
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

    df_vulns = get_vulnerability_data_from_json(json_data)
    join_everything_to_top_level(json_data)


if __name__ == "__main__":
    main()