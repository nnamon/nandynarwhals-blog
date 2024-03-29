#include "pch.h"
#include <iostream>

int InputNumber()
{
	using namespace std;

	char innum[11] = "";
	int num;
	bool f;

	cout << "Determine whether the number you entered is even or odd." << endl;

	while (true)
	{
		num = 0;
		f = false;

		cout << "Input number, please " << endl;
		cin >> innum;

		for (int i = 0; i < sizeof(innum); i++)
		{
			if (innum[i] > 0)
			{
				if (not (innum[i] >= '0' && innum[i] <= '9'))
				{
					cout << "Input number only." << endl;
					f = false;
					break;
				}
				else {
					int j = innum[i] - '0';
					num = num * 10 + j;
					f = true;
				}
			}
		}

		if (f == true)
		{
			return num;
		}

		signed a = innum[0];
		unsigned b = innum[0];
	}
}

std::string GetFlag(int key)
{
	std::string val = "";

	if (key * 2 == 2)
	{
		<<Deleted>>
	}
	else {
		val = "Close! Please enter close to the limit value to get a flag.";
	}

	return val.c_str();
}

int main()
{
	using namespace std;

	int num;

	num = InputNumber();
	std::string msg;

	if (num % 2 == 0)
	{
		msg = "The number you input is even.\n";
	} else if (num % 2 == 1){
		msg = "The number you input is odd.\n";
	}
	else {
		msg = GetFlag(num);
	}

	printf("%s\n", msg.c_str());
}
