#include <bits/stdc++.h>
#include <string>
using namespace std;
int main()
{
    ///lowercase letters are in Caesar cyper +9 and uppercase letters +2
    char c[200] = " bcjac --- YnuNmQPGhQWqCXGUxuXnFVqrUVCUMhQdaHuCIrbDIcUqnKxbPORYTzVCDBlmAqtKnEJcpED --- UVQR ";
    char rez[200] = {0};
    int z = 0;
    int lg = strlen(c);
    for(int i=0; i<lg; ++i)
        if(isupper(c[i]))
        {
            if(c[i] - 2 < 'A')
                rez[z++]=('Z' + ( -('A' - c[i]) - 2) + 1);
            else rez[z++]=(c[i]-2);
        }
        else if(islower(c[i]))
        {
            if(c[i] - 9 < 'a')
                rez[z++]=('z' + ( -('a' - c[i]) - 9) + 1);
            else rez[z++]=(c[i]-9);
        }
        else rez[z++]=c[i];
    rez[z] = 0;
    ///maximum laziness (404 brain)
    char rez2[100]={0};
    int lg2 = 0;
    for(int i=0; i<lg; ++i)
	    if(tolower(rez[i]) == 'f' && tolower(rez[i+1]) == 'l'
				    && tolower(rez[i+2]) == 'a'
				    && tolower(rez[i+3]) == 'g'
				    && tolower(rez[i+4]) == 'i'
				    && tolower(rez[i+5]) == 's')
	    {		for(int j=i+6; rez[j]!=' '; ++j)
		    		rez2[lg2++]=rez[j];
		    break;
	    }
    rez2[lg] = 0;
    printf("ECSC{%s}", rez2);
}
