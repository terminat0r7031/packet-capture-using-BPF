#ifndef PARSER_H
#define PARSER_H

#include <stdlib.h>
#include <iostream>
#include <queue>
#include <vector>
#include <stack>
#include <string>
#include <ctype.h>			// for isalnum()
#include <linux/filter.h>	// for struct sock_filter  && struct sock_fprog
#include <stdint.h>			// for uint8_t and uint32_t
#include <netinet/in.h>		// for struct sockaddr_in

#include <arpa/inet.h>		// for inet_aton()		
#include <stdio.h>

#include "ExtendStructure.h"	// for struct my_sock_filter

using namespace std;

struct BlockCode {
	queue<my_sock_filter> codeSegment;
};

class Parser{
	private:
		queue<string> tokens;
		queue<string> postFix;
		uint8_t offOr;
		uint8_t offAnd;
		int isField(string token);
		int getPriority(string op);
		int isOperator(string op);
		void convertToPostfix();
		struct BlockCode genCmp(string field, string value);
		struct BlockCode genCmp(string field, string value, string op);
		struct BlockCode genOr(struct BlockCode b1, struct BlockCode b2);
		struct BlockCode genAnd(struct BlockCode b1, struct BlockCode b2); 
		struct BlockCode genFilterIP(struct BlockCode b1);
		struct BlockCode genRet(struct BlockCode b1);

	public:
		Parser();
		void lexicalAnalysis(const string expr);
		void genCode(struct sock_filter *bpfCode, struct sock_fprog *bpfProg);
};

#endif