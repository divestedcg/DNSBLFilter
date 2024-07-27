/*
Copyright (c) 2016-2019 Divested Computing Group

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <algorithm>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>

using namespace std;

unordered_set<string> arrCompanies;
unordered_set<string> arrKeywords;
unordered_set<string> arrKeywordsSplit;
unordered_set<string> arrDomainsMaliciousCombined;

void analyzeDomain(const string domain, unordered_set<string> &arrDomainsMalicious) {
	bool malicious = false;
	istringstream domainSS(domain);
	string token;
	int c = 0;
	int amtSplit = count(domain.begin(), domain.end(), '.');
	while(getline(domainSS, token, '.')) {
		if(c < amtSplit) {//Ignore the TLD
			if(arrCompanies.count(token) > 0) {
				malicious = true;
			}
		}
		if(c < amtSplit - 1) {//Ignore the TLD and the domain
			if(arrKeywords.count(token) > 0 || arrKeywordsSplit.count(token) > 0) {
				malicious = true;
			}
		}
		c++;
	}
	if(malicious) {
		arrDomainsMalicious.insert(domain);
	}
}

void loadFileToArray(const string file, unordered_set<string> &array) {
	ifstream fileIn;
	string lineIn;
	fileIn.open(file);
	while(getline(fileIn, lineIn)) {
		array.insert(lineIn);
	}
	fileIn.close();
}

void loadCompanyList(const string file, unordered_set<string> &allowlist) {
	ifstream fileIn;
	string lineIn;
	fileIn.open(file);
	while(getline(fileIn, lineIn)) {
		if(allowlist.count(lineIn) == 0) {
			arrCompanies.insert(lineIn);
		}
	}
	fileIn.close();
}

void analyzeDomainList(const int threadID, const string file) {
	ifstream fileIn;
	string lineIn;
	unordered_set<string> arrDomainsMalicious;
	int amtDomains = 0;
	fileIn.open(file);
	while(getline(fileIn, lineIn)) {
		analyzeDomain(lineIn, arrDomainsMalicious);
		amtDomains++;
		if(amtDomains % 10000000 == 0) {
			cout << "[" << threadID << "] Analyzed " << amtDomains << " domains so far\n";
		}
	}
	fileIn.close();
	arrDomainsMaliciousCombined.insert(arrDomainsMalicious.begin(), arrDomainsMalicious.end());
	cout << "[" << threadID << "] Added " << arrDomainsMalicious.size() << " malicious domains\n";
}

void writeSetToFile(const string file, set<string> &array) {
	ofstream fileOut;
	fileOut.open(file);
	for(string entry : array) {
		fileOut << entry << "\n";
	}
	fileOut.close();
}

int main() {
	cout << "Loading lists...\n";
	unordered_set<string> arrAllowlist;
	loadFileToArray("Filters/Allowlist.txt", arrAllowlist);
	loadFileToArray("Filters/Keywords.txt", arrKeywords);
	loadFileToArray("Filters/KeywordsSplit.txt", arrKeywordsSplit);
	loadCompanyList("Filters/Companies-Primary.txt", arrAllowlist);
	loadCompanyList("Filters/Companies-Martech.txt", arrAllowlist);
	loadCompanyList("Filters/Companies-Better.txt", arrAllowlist);
	loadCompanyList("Filters/Companies-Quids.txt", arrAllowlist);

	const int totalKeywords = (arrCompanies.size() + arrKeywords.size() + arrKeywordsSplit.size());
	cout << "Loaded " << totalKeywords << " matchers\n";
	cout << "\t" << arrCompanies.size() << " companies\n";
	cout << "\t" << arrKeywords.size() << " keywords\n";
	cout << "\t" << arrKeywordsSplit.size() << " split keywords\n\n";

	cout << "Analyzing domains...\n";
	int threadCounter = 0;
	thread adl1(analyzeDomainList, ++threadCounter, "Domains.txt");
	adl1.join();
	cout << "Analyzed domains\n\n";

	cout << "Sorting...\n";
	set<string> arrDomainsMaliciousSorted;
	arrDomainsMaliciousSorted.insert(arrDomainsMaliciousCombined.begin(), arrDomainsMaliciousCombined.end());
	cout << "Sorted\n\n";

	cout << "Writing out...\n";
	writeSetToFile("Generated/ExperimentalV4-UP.txt", arrDomainsMaliciousSorted);
	cout << "Wrote out " << arrDomainsMaliciousSorted.size() << " malicious domains\n\n";
}
