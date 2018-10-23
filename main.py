from requests import get
from requests.exceptions import RequestException
from time import sleep
from itertools import cycle
import pandas as pd


def extract():
    if filter_level in [2, 3, 6]:
        date = input("Initial date (dd/mm/yyyy): ")
        date = [int(x) for x in date.split('/')]
        datetime = pd.Timestamp(day=date[0], month=date[1], year=date[2])
    if filter_level in [3, 4, 6]:
        date = input("Final date (dd/mm/yyyy): ")
        date = [int(x) for x in date.split('/')]
        datetime_final = pd.Timestamp(day=date[0], month=date[1], year=date[2])

    csv = pd.read_csv('export.csv', usecols=['Created', 'Modified', 'MD5'])
    csv['Created'] = pd.to_datetime(csv['Created'])
    csv['Modified'] = pd.to_datetime(csv['Modified'])

    if filter_level in [2, 3, 6]:
        csv = csv[(csv['Created'] >= datetime) | (csv['Modified'] >= datetime)]
    if filter_level in [3, 4, 6]:
        csv = csv[(csv['Created'] < datetime_final) |
                  (csv['Modified'] < datetime_final)]
    if filter_level in [5, 6]:
        csv = csv[csv['Created'] > csv['Modified']]

    hashes = [line.split()[-1] for line in csv['MD5']
              if not line.endswith(" ")]

    with open('hashes.txt', 'w') as f:
        for line in hashes:
            f.write(line + '\n')


def request_report():
    hashes = []
    failed_hashes = []

    with open("report.txt", "w"):
        pass

    with open("hashes.txt", "r") as f:
        for line in f.readlines():
            hashes.append(line.rstrip())

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    payload = {}
    api_loop = cycle(api_keys)

    for line in hashes:
        payload['apikey'] = next(api_loop)
        payload['resource'] = line

        try:
            response = get(url, params=payload)
        except RequestException as e:
            print(f"Error at resource: {line}")
            print(e)
            print("")
            failed_hashes.append(line)
            continue

        response_json = response.json()
        report = get_report(response_json)
        save_report(report)

        for info in report:
            print(info)

        sleep(15 / len(api_keys))

    for i in range(2):
        if failed_hashes:
            for line in failed_hashes:
                payload['apikey'] = next(api_loop)
                payload['resource'] = line

                try:
                    response = get(url, params=payload)
                except RequestException as e:
                    print(f"Error at resource: {line}")
                    print(e)
                    print("")
                    continue

                response_json = response.json()
                report = get_report(response_json)
                save_report(report)
                failed_hashes.remove(line)

                for info in report:
                    print(info)

                sleep(15 / len(api_keys))
        else:
            print("\nNo errors. Is this a miracle??")
            break

    keep_going = input(f"{len(failed_hashes)} hashes failed 3 times."
                       " Keep trying? (Y/n)") or "Y"

    if keep_going.lower() == "y":
        while failed_hashes:
            for line in failed_hashes:
                payload['apikey'] = next(api_loop)
                payload['resource'] = line

                try:
                    response = get(url, params=payload, timeout=5)
                except RequestException as e:
                    print(f"Error at resource: {line}")
                    print(e)
                    print("")
                    continue

                response_json = response.json()
                report = get_report(response_json)
                save_report(report)
                failed_hashes.remove(line)

                for info in report:
                    print(info)

                sleep(15 / len(api_keys))
        print("\nAaaand we're done")


def get_report(response_json):
    report = []

    report.append("Resource: {}".format(response_json['resource']))
    report.append("Message: {}".format(response_json['verbose_msg']))
    if response_json['response_code'] == 1:
        report.append("Scan date: {}".format(response_json['scan_date']))
        report.append("Positives: {}/{}"
                      .format(response_json['positives'],
                              response_json['total']))
        report.append("Permalink: {}".format(response_json['permalink']))
    report.append("")

    return report


def save_report(report_lines):
    with open("report.txt", "a") as f:
        for line in report_lines:
            f.write(line + "\n")


if __name__ == "__main__":
    api_keys = []
    try:
        with open("apikeys.txt", "r") as keys_file:
            for line in keys_file:
                api_keys.append(line)
    except IOError as e:
        print("Couldn't find apikeys.txt file. Please create it.")
        exit(1)

    print("--Filter levels--\n")
    print("1- No filter")
    print("2- Filter files created or modified after given date")
    print("3- Filter files created or modified between given dates")
    print("4- Filter files created or modified before given date")
    print("5- Filter files modified before creation")
    print("6- 3 and 5\n")
    filter_level = int(input("Filter level (default 1): ") or "1")
    print("")
    extract()
    request_report()
