#include<bits/stdc++.h>
using namespace std;

class Virus{
    public:
        string HashValue;
        string Name;
    public:
        Virus(string="",string="");
};

Virus::Virus(string hash,string name){
    HashValue=hash;
    Name=name;
}

bool Cmp(Virus a,Virus b){
    return a.HashValue<b.HashValue;
}

class ResultScan{
    public:
        bool isEmpty;
        string VirusName;
    public:
        ResultScan(bool=false,string="");
};

ResultScan::ResultScan(bool isempty,string name){
    isEmpty=isempty;
    VirusName=name;
}

class HashScannerZ{
    public:
        string pathz[8];
        vector<Virus> lst[8];
        vector<Virus> tmpZ;
        FILE *pFile;
        int Size;
    public:
        HashScannerZ();
        Virus getVirus(int pos);
        int ConvertCharToNum(char);
        ResultScan BinarySearch(string="");
        ResultScan Search(string="");
        ResultScan Scan(string="");
        string getMD5(string="");
        void Update(string="");
        void LoadDB(string="");
};

HashScannerZ::HashScannerZ(){
    pathz[0]="MD5_01";
    pathz[1]="MD5_23";
    pathz[2]="MD5_45";
    pathz[3]="MD5_67";
    pathz[4]="MD5_89";
    pathz[5]="MD5_AB";
    pathz[6]="MD5_CD";
    pathz[7]="MD5_EF";
}

Virus HashScannerZ::getVirus(int pos){
    pos--;
    char vct[75];
    fseek(pFile,pos*75,SEEK_SET);
    fread(vct,sizeof(char),75,pFile);
    for (int i=0;i<75;i++)
        if (vct[i]<0) vct[i]=-vct[i]-1;
        else vct[i]=255-vct[i];
    //for(int i=0;i<75;i++) cout<<vct[i];cout<<endl;
    string Hash="";
    for(int i=0;i<32;i++) Hash=Hash+vct[i];
    string Name="";
    for(int i=33;i<75;i++)
        if (vct[i]!=' ')
            Name=Name+vct[i];
    Virus res=Virus(Hash,Name);
    return res;
}

int HashScannerZ::ConvertCharToNum(char ch){
    //cout<<"Ch= "<<ch<<endl;
    switch (ch)
    {
        case '0':
        case '1':
            return 0;
        case '2':
        case '3':
            return 1;
        case '4':
        case '5':
            return 2;
        case '6':
        case '7':
            return 3;
        case '8':
        case '9':
            return 4;
        case 'a':
        case 'b':
            return 5;
        case 'c':
        case 'd':
            return 6;
        case 'e':
        case 'f':
            return 7;
        default:
            break;
    }
}

ResultScan HashScannerZ::BinarySearch(string hashValue){
    int inf=1;int sup=Size;
    //Virus t=getVirus(1);
    //cout<<t.Hash<<"+"<<t.Name<<endl;
    while(inf<=sup){
        //cout<<"Inf= "<<inf<<" Sup= "<<sup<<endl;
        int mid=(inf+sup)/2;
        Virus tmp=getVirus(mid);
        //cout<<"Mid= "<<mid<<"-> "<<tmp.Hash<<" "<<tmp.Name<<endl;
        if (tmp.HashValue==hashValue){
            ResultScan res=ResultScan(false,tmp.Name);
            return res;
        }
        if (tmp.HashValue<hashValue) inf=mid+1;
        else sup=mid-1;
    }
    ResultScan res=ResultScan(true,"");
    return res;
}

ResultScan HashScannerZ::Search(string hashValue){
    int id=ConvertCharToNum(hashValue[0]);
    //cout<<"Id= "<<id<<endl;
    pFile=fopen(pathz[id].c_str(),"rb");
    fseek(pFile,0,SEEK_END);
    Size=ftell(pFile)/75;
    fseek(pFile,0,SEEK_SET);
    ResultScan res=BinarySearch(hashValue);
    fclose(pFile);
    return res;
}

ResultScan HashScannerZ::Scan(string Path){
    string MD5=getMD5(Path);
    return Search(MD5);
}

string HashScannerZ::getMD5(string Path){
    string path='"'+Path+'"';
    string cmd="md5sum "+path+" > res.txt";
    cout<<cmd<<endl;
    system(cmd.c_str());
    ifstream fi("res.txt");
    string res;
    fi>>res;
    return res;
}

void HashScannerZ::Update(string Path){
    for(int i=0;i<8;i++) lst[i].clear();
    fstream fi;
    fi.open(Path.c_str(),ios::in);
    string s;
    while(fi>>s){
        int l=s.length();
        int i=s.find(':');
        string hash=s.substr(0,i); // From 0 to i-1
        string name=s.substr(i+1,l-i-1); // From i+1 to l-1
        if (Search(hash).isEmpty==true){
            Virus t=Virus(hash,name);
            int id=ConvertCharToNum(hash[0]);
            lst[id].push_back(t);
        }
    }
    fi.close();
    //----------
    for(int id=0;id<8;id++)
        if (lst[id].size()>0)
        {
            //cout<<"Id= "<<id<<endl;
            tmpZ.clear();
            for(int i=0;i<lst[id].size();i++)
                tmpZ.push_back(lst[id][i]);
            //---------
            pFile=fopen(pathz[id].c_str(),"rb");
            fseek(pFile,0,SEEK_END);
            Size=ftell(pFile)/75;
            fseek(pFile,0,SEEK_SET);
            for(int i=1;i<=Size;i++){
                Virus t=getVirus(i);
                tmpZ.push_back(t);
            }
            fclose(pFile);
            //--------
            sort(tmpZ.begin(),tmpZ.end(),Cmp);
            fi.open(pathz[id].c_str(),ios::out);
            for(int i=0;i<tmpZ.size();i++){
                string st=tmpZ[i].HashValue+":"+tmpZ[i].Name;
                int l=st.length();
                for(int j=0;j<75;j++)
                    if (j<l) fi<<char(255-st[j]);
                    else fi<<char(255-32);
            }
            fi.close();
        }
}

void HashScannerZ::LoadDB(string Path){
    pFile=fopen(Path.c_str(),"rb");
    fseek(pFile,0,SEEK_END);Size=ftell(pFile)/75;
    fseek(pFile,0,SEEK_SET);
    fstream f;f.open("res.txt",ios::out);
    for(int i=1;i<=Size;i++){
        Virus t=getVirus(i);
        f<<t.HashValue<<":"<<t.Name<<endl;
    }
    fclose(pFile);f.close();
}

int main(){
    HashScannerZ hash=HashScannerZ();
    //cout<<hash.getMD5("PCapy.py")<<endl;
    //cout<<hash.Scan("Untitled X.exe").isVirus;
    //hash.LoadDB("MD5_89");
    hash.Update("Update.txt");
    //ReadFile();
}
