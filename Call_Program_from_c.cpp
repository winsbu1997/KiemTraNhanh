#include <bits/stdc++.h>
using namespace std;

int main()
{
    string str1 = "python test.py ";
    str1 = str1 + "-r " ;//+ "nokia";
    system(str1.c_str());
    //system("ls");
    char filename[100];
    cout << "Enter file name to compile ";
    cin.getline(filename, 100);
    string str = "g++ ";
    str = str + filename + " -o a";

    const char *command = str.c_str();
    cout << "Compiling file using " << command << endl;
    system(command);
    cout << "\nRunning file ";
    system("/home/duong/Desktop/Do-An/QuickCheck_Virus/a");

    //string str = "python ";
    //str = str + filename;
    //system(str.c_str());
    return 0;
}