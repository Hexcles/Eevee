/* 
 * FileCompare.cpp
 *  
 * This file is part of Eevee.
 * 
 * Copyright (C) 2012 Hexcles Ma <bob1211@gmail.com>
 * 
 * Eevee is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Eevee is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Eevee.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <sys/stat.h>
#include <memory.h>
#include <sysexits.h>
#include <string>
#include <iostream>
#include <fstream>
#define EX_SAME 1
#define EX_DIFF 0
#define STRICT_MODE 1
#define NORMAL_MODE 0
#define BUFF_SIZE 65536
using namespace std;

int MODE = NORMAL_MODE;
char *filename1 = NULL, *filename2 = NULL;
char buf1[BUFF_SIZE], buf2[BUFF_SIZE];
string str1, str2;

void printusage() {
	puts("FileCompare v0.2");
	puts("Usage:\tFileCompare StdFile UsrFile [--mode {strict|normal}]");
	puts("若两文件一致返回值为1，否则返回为0，发生错误返回BSD标准错误代码。");
	puts("");
	puts("--mode\t默认为normal");
	puts("\tnormal\t正常模式，忽略行末空格和文末回车。");
	puts("\tstrict\t严格模式，判断是否两文件严格一致。");
	puts("--help\t显示此帮助");
}

inline void trim(string &str) {
	while (str.length() > 0 && *(str.end() - 1) == ' ') str.erase(str.end() - 1);
}

int normal_compare() {
	//compare file size
	struct stat s1, s2;
	stat(filename1, &s1);
	stat(filename2, &s2);
	if (s2.st_size < s1.st_size / 2 || s2.st_size > s1.st_size * 2) return EX_DIFF;
	//compare file content
	ifstream fin1(filename1, ifstream::in), fin2(filename2, ifstream::in);
	fin1.sync_with_stdio(false);
	fin2.sync_with_stdio(false);
	str1.reserve(BUFF_SIZE);
	str2.reserve(BUFF_SIZE);
	while (fin1.good() || fin2.good()) {
		if (fin1.good()) {
			getline(fin1, str1);
			trim(str1);
		} else str1 = "";
		if (fin2.good()) {
			getline(fin2, str2);
			trim(str2);
		} else str2 = "";
		if (str1 != str2){
			cout << str1 << endl;
			cout << str2 << endl;
			return EX_DIFF;
		}
	}
	return EX_SAME;
}

int strict_compare() {
	//compare file size
	size_t len;
	struct stat s1, s2;
	stat(filename1, &s1);
	stat(filename2, &s2);
	if (s1.st_size != s2.st_size) return EX_DIFF;
	//compare file content
	FILE *fp1, *fp2;
	fp1 = fopen(filename1, "rb");
	fp2 = fopen(filename2, "rb");
	while (!feof(fp1)) {
		len = fread(buf1, 1, sizeof(buf1), fp1);
		fread(buf2, 1, sizeof(buf2), fp2);
		if (memcmp(buf1, buf2, len)) return EX_DIFF;
	}
	return EX_SAME;
}

int main(int argc, char *argv[]) {
	//Process the argument
	if (argc != 2 && argc != 3 && argc != 5) {
		printusage();
		return EX_USAGE;
	}
	for (int i = 1; i < argc; ++ i) {
		if (!strcmp(argv[i], "--mode")) {
			if (i == argc - 1) {
				printusage();
				return EX_USAGE;
			}
			++ i;
			if (!strcmp(argv[i], "strict")) MODE = STRICT_MODE;
			else if(!strcmp(argv[i], "normal")) MODE = NORMAL_MODE;
			else {
				printusage();
				return EX_USAGE;
			}
		} else if (!strcmp(argv[i], "--help")){
			printusage();
			return EX_USAGE;
		} else {
			if (filename1) filename2 = argv[i];
			else filename1 = argv[i];
		}
	}
	if (!filename1 || !filename2) {
		printusage();
		return EX_USAGE;
	}
	if (access(filename1, R_OK) || access(filename2, R_OK)) {
		fprintf(stderr, "Error: can not open file.\n");
		return EX_NOINPUT;
	}
	//Do compare
	switch (MODE) {
		case NORMAL_MODE: return normal_compare();
		case STRICT_MODE: return strict_compare();
	}
	return EX_USAGE;
}
