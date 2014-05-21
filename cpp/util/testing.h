#ifndef TESTING_H
#define TESTING_H

namespace ct {
namespace test {

void InitTesting(const char *name, int *argc, char ***argv,
                 bool remove_flags);

}  // namespace test
}  // namespace ct
#endif
