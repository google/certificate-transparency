package gomerkletree

import "testing"

func TestLargestPowerOfTwoLessThan(t *testing.T) {
	test_data := []struct {
		input, output uint64
	} {
		{2,  1},
		{3,  2},
		{4,  2},
		{5,  4},
		{7,  4},
		{8,  4},
		{9,  8},
		{15, 8},
		{16, 8},
		{17, 16},
		{1048576, 524288},
		{1048577, 1048576},
	}

	for _, td := range test_data {
		actual := largestPowerOfTwoLessThan(td.input)

		if actual != td.output {
			t.Errorf("largestPowerOfTwoLessThan(%v) => %v, expected %v", td.input, actual, td.output)
		}
	}
}
