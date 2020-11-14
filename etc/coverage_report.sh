#!/bin/bash
#
# Create a code-coverage report locally and upload one to codecov
# Should be run from the root directory

if [ -r coverage_report.sh ]; then
    echo "coverage_report.sh run in /etc directory. moving to .."
    cd ..
fi

#make distclean
#CFLAGS="--coverage" CXXFLAGS="--coverage" LDFLAGS="--coverage" ./configure
make check
lcov --capture --directory . --output-file main_coverage.info
genhtml main_coverage.info --output-directory out

# Upload the coverage report
bash <(curl -s https://codecov.io/bash)

/bin/rm -f *.gcov *.gcda *.gcno

