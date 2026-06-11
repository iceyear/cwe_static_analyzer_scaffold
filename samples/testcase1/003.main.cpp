#include "schedule.h"
#include "schedule.cpp"
ofstream log;
volatile bool exiting;

void helpInfo()
{
	cout<<"*******************\n";
	cout<<"COMMANDLIST:\n";
	cout<<"create process_name process_length(create p0 8)\n";
	cout<<"\t append a process to the process list\n";
	cout<<"remove process_name(remove p0)\n";
	cout<<"\t remove a process from the process list\n";
	cout<<"current\t show current runprocess readtList\n";
	cout<<"exit\t show current runprocess readyList\n";
	cout<<"help\t get command information\n";
	cout<<"*******************\n\n";
}

int main()
{
	char name[20]={'\0'};
	HANDLE hSchedule;
	log.open("Process_log.txt");
	helpInfo();
	hSchedule=init();
	if(hSchedule==NULL)
	{
		cout<<"\nCreate schedule-process failed.System will abort!"<<endl;
		exiting=true;
	}
	char command[30]={0};
	while(!exiting)
	{
		cout<<"COMMAND>";
		cin>>command;
		if(strcmp(command,"exit")==0)
		break;
		else if(strcmp(command,"create")==0)
		{
			char name[20]={'\0'};
			int time=0;
			cin>>name>>time;
			createProcess(name,time);
		}
		else if(strcmp(command,"remove")==0)
		{
			cin>>name;
			removeProcess(name);
		}
		else if(strcmp(command,"current")==0)
		     printCurrent();
	    else if(strcmp(command,"help")==0)
	         helpInfo();
	    else
	    cout<<"Enter help to get command information!\n";
	}
	exiting=true;
	
	if(hSchedule!=NULL)
	{
		WaitForSingleObject(hSchedule,INFINITE);
		CloseHandle(hSchedule);
	}
	log.close();
	cout<<"\n******End*******\n"<<endl;
	return 0;
}
