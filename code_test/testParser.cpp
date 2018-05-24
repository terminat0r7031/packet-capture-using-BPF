#include "Parser.cpp"
#include <string>
#include <vector>
#include <iostream>
#include <linux/filter.h>

int main(){
	Parser parser;
	parser.lexicalAnalysis(" src == 10.10.10.10 || src == 20.20.20.20 &&  dst == 30.30.30.30 ");
}