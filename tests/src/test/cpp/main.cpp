/*
 * main.cpp
 *
 *  Created on: Apr 7, 2016
 *      Author: padolph
 */

#include <crypto/OpenSslLib.h>
#include "gtest/gtest.h"
#include <stdlib.h>
#include <iostream>
#include <unistd.h>

using namespace std;

namespace netflix { namespace msl {
extern int g_exBacktraceDepth;   // defined in Exception.cpp
}}

int main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  int c;
  opterr = 0;
  while ((c = getopt (argc, argv, "d:")) != -1) {
      switch (c) {
          case 'd':
              netflix::msl::g_exBacktraceDepth = atoi(optarg)+1;
              break;
          default:
              std::cout << "bad command line args" << endl;
              break;
      }
  }
  return RUN_ALL_TESTS();
  netflix::msl::crypto::shutdownOpenSsl();
}
