#include "schedule.h"
readyList readylist; //定义就绪队列的管理结构
pList pReadyList=&readylist;//定义该结构的指针
freeList freelist;
pList pFreeList=&freelist; 
PCB pcb[PCB_LIMIT];    //定义30个PCB
pPCB runPCB;
int pid=0;
//进程id(创建进程用)
//临界区对象
CRITICAL_SECTION cs_ReadyList;//用于互斥访问就绪队列
CRITICAL_SECTION cs_SaveInfo;//用于互斥访问保存信息的文件
//输出文件
extern ofstream log;
extern volatile bool exiting; //当 exiting -true时程序结束
//初始化进程控制块
void initialPCB(pPCB p)
{
p->id=0; //进程 id
strcpy(p->name,"NoName");//进程名字
p->status=WAIT; //进程状态
p->next=NULL; //PCB 的next指针
p->hThis=NULL; //进 程句柄
p->threadID=0;
//线程id
p->flag=1;
//开始时允许线程显示信息
p->count=0;
//进程计划运行时间
}
//从空白PCB队列取- -空闲进程控制块
pPCB getPcbFromFreeList()
{
   pPCB freePCB=NULL;
   if(pFreeList->head!=NULL&&pFreeList->pcbNum>0)
   {
     freePCB=pFreeList->head;
     pFreeList->head=pFreeList->head->next;
     pFreeList->pcbNum--;
   }
     return freePCB; //释放PCB使之插入空闲PCB队列
}
void returnPcbToFreeList(pPCB p)
{
   if(pFreeList->head==NULL) //若当前空闲PCB队列为空
   {
     pFreeList->head=p;
     pFreeList->tail=p;
     p->next=NULL;
     pFreeList->pcbNum++;
   }
   else  //若空白PCB队列不空，则将释放的PCB插入队首
   {
     p->next=pFreeList->head;
     pFreeList->head=p;
     pFreeList->pcbNum++;
   }
}

//模拟用户进程的线程之执行代码
DWORD WINAPI processThread(LPVOID lpParameter)
{
  pPCB currentPcb=(pPCB)lpParameter;
  while(true)
  { 
    if(currentPcb->flag==1)//若调度后第一次运行， 则显示信息
      {
	    currentPcb->flag=0;
        EnterCriticalSection(&cs_SaveInfo);//“进程正在运行”信息保存到文件
        log<<"Process"<<currentPcb->id<<':'<<currentPcb->name
		   <<"is running......"<<endl;
        LeaveCriticalSection(&cs_SaveInfo);//离开临界区
      }
      Sleep(800);
  }
   return 1;
}


DWORD WINAPI scheduleThread(LPVOID lpParameter)
{
   while (!exiting) //若exiting-false,则循环执行调度程序
   {
     scheduleProcess();
   }
   stopAllThreads();//若exting- true,则结束所有进程(线程)
   return 1;
}

//初始化操作
HANDLE init()//函数正确执行后，返回调度线程的句柄
{
   pPCB p=pcb; //指向第一个 PCB
//就绪队列初始化为空(初始化其管理结构)
pReadyList->head=NULL;
pReadyList->tail=NULL;
pReadyList->pcbNum=0;
//空闲队列初始化为空(初始化其管理结构)
pFreeList->head=&pcb[0];
pFreeList->tail=&pcb[PCB_LIMIT-1];
pFreeList->pcbNum=PCB_LIMIT;
//构成空闲PCB队列
for(int i=0;i<PCB_LIMIT-1;i++)
{
  initialPCB(p);
  p->next=&pcb[i+1];
  p++;
}
initialPCB(p);
pcb[PCB_LIMIT-1].next=NULL;
InitializeCriticalSection(&cs_ReadyList);
InitializeCriticalSection(&cs_SaveInfo);
exiting=false;
HANDLE hSchedule;//程序调度线程的句柄
hSchedule=CreateThread(
NULL,
0,
scheduleThread, 
pReadyList, 
0,
NULL
);

char pName[6]="p00";
int i;
for(i=0;i<6;i++)
 {
  pName[2]='0'+i;
  createProcess(pName,10);
 } 
  return hSchedule;
}

void createProcess(char *name,int count)
{
  EnterCriticalSection(&cs_ReadyList); //M准各进入临界区
  if(pFreeList->pcbNum>0) //" 若有用于创建进程的空白PCB
  {
    pPCB newPcb=getPcbFromFreeList();//从空白PCB以列获取个空百PCB
    newPcb->status=READY;//新造程状态为“READY
    strcpy(newPcb->name,name); //填写新进程的名字
    newPcb->count=count;
    newPcb->id=pid++;
    newPcb->next=NULL;
    if(pReadyList->pcbNum==0)
   {
     pReadyList->head=newPcb;
     pReadyList->tail=newPcb;
     pReadyList->pcbNum++;
   }
    else
   {
     pReadyList->tail->next=newPcb;
     pReadyList->tail=newPcb;
     pReadyList->pcbNum++;
   }
cout<<"New Process Created,Proces ID:"
    <<newPcb->id<<",Proces Name:"
	<<newPcb->name<<",Procsss Length:"
	<<newPcb->count<<endl;
cout<<"Current ReadyList is:"<<endl;
printReadyList();
//向信息文件输出相关信息以便查看程序执行过程
EnterCriticalSection(&cs_SaveInfo);
log<<"New Process Created,Process ID:"
   <<newPcb->id<<",Process Name:"
   <<newPcb->name<<",Proess Length:"<<newPcb->count<<endl;
log<<"Current ReadyList is:"<<endl;
fprintReadyList();
LeaveCriticalSection(&cs_SaveInfo);
//创建用户线程，初始状态为暂停
newPcb->hThis=CreateThread(NULL,0,processThread,newPcb,CREATE_SUSPENDED,&(newPcb->threadID));
}
else
 {
   cout<<"New process intend 1o append.But PCB has been used out!"<<endl;
   EnterCriticalSection(&cs_SaveInfo);
   log<<"New process intend to append.But PCB has been used out"<<endl;
   LeaveCriticalSection(&cs_SaveInfo);
 }
   LeaveCriticalSection(&cs_ReadyList); 
}
  
void scheduleProcess()
{
  EnterCriticalSection(&cs_ReadyList);
  if(pReadyList->pcbNum>0) //就绪队列中有进程则调度
 {
  runPCB=pReadyList->head; 
  pReadyList->head=pReadyList->head->next; //修改就绪队列的头指针
  if(pReadyList->head==NULL) //若就绪队列已空。则需修改其尼指针
     pReadyList->tail=NULL;
  pReadyList->pcbNum--; //就绪队列节点数减1
  runPCB->count--;
  runPCB->flag=1;
  EnterCriticalSection(&cs_SaveInfo);
  log<<"Process"<<runPCB->id<<':'<<runPCB->name<<"is to be schedule"<<endl;
  LeaveCriticalSection(&cs_SaveInfo);
  ResumeThread(runPCB->hThis);//恢复线程(进程)。在本程序中实际上是启动线程运行
  runPCB->status=RUN;

Sleep(1000);
EnterCriticalSection(&cs_SaveInfo);
log<<"\nOne time slot used out!\n"<<endl;
LeaveCriticalSection(&cs_SaveInfo);
runPCB->status=READY;
SuspendThread(runPCB->hThis); 
if(runPCB!=NULL&&runPCB->count<=0)
{
  cout<<"\n***** Process"<<runPCB->id<<':'<<runPCB->name
      <<"has finished.******"<<endl;
  cout<<"Current ReadyList is:"<<endl;
  printReadyList();
  cout<<"COMMAND>";cout<<flush;
  EnterCriticalSection(&cs_SaveInfo);
  log<<"***** Process"<<runPCB->id<<':'<<runPCB->name
     <<"has finished.*****\n"<<endl;
  log<<"Current ReadyList is:"<<endl;
  fprintReadyList();
  log<<flush;
  LeaveCriticalSection(&cs_SaveInfo); 
  if(!TerminateThread(runPCB->hThis,1))
 { 
   EnterCriticalSection(&cs_SaveInfo);
   log<<"Terminate thread failed!System will abort!"<<endl;
   LeaveCriticalSection(&cs_SaveInfo);
   exiting=true; //结束程序
 }
  else
  {
	CloseHandle(runPCB->hThis);
    returnPcbToFreeList(runPCB);
    runPCB=NULL;
  }
}
else if (runPCB!=NULL) //进程未运行完毕，则将其插入就绪队列
 { 
  if(pReadyList->pcbNum<=0)//就绪队列为空时的处理
  { 
    pReadyList->head=runPCB;
    pReadyList->tail=runPCB;
  } 
  else	
  {
    pReadyList->tail->next=runPCB;
    pReadyList->tail=runPCB;
  } 
    runPCB->next=NULL;
    runPCB=NULL;
    pReadyList->pcbNum++; //就绪队列进程数增 1
  }
}
else if(pReadyList!=NULL) // 清空就绪队列
  {   
   pReadyList->head=NULL;
   pReadyList->tail=NULL;
   pReadyList->pcbNum=0;
  }
LeaveCriticalSection(&cs_ReadyList);
}

// 撤销进程
void removeProcess(char *name)
{
pPCB removeTarget=NULL;
pPCB preTemp=NULL;
EnterCriticalSection(&cs_ReadyList); //互斥访问就绪队列
//若撤销的是当前运行进程
if (runPCB!=NULL&&strcmp(name,runPCB->name)==0)
{
	removeTarget=runPCB;
	if(!(TerminateThread(removeTarget->hThis,1)))
   {
	cout<<"Terminate thread failed! System will abort!"<<endl;
    EnterCriticalSection(&cs_SaveInfo);
    log<<"Terminate thread failed! System will abort!"<<endl;
    LeaveCriticalSection(&cs_SaveInfo);
    exit(0);//结束程序
   }
else //撤销操作成功时
  {
    CloseHandle(removeTarget->hThis); //关闭进 程句柄
    returnPcbToFreeList(removeTarget); //该进程的 PCB插入空闲PCB队列
    runPCB=NULL;
    //显示进程已撤销的信息
    cout<<*"\nProcess"<<removeTarget->id
        <<':'<<removeTarget->name<<"has been removed."<<endl;
    cout<<"Current ReadyList is:\n";
    printReadyList();
    EnterCriticalSection(&cs_SaveInfo);
    log<<"\nProcess"<<removeTarget->id
       <<':'<<removeTarget->name<<"has been removed."<<endl;
    log<<"Current ReadyList is:\n";
    fprintReadyList();
    log<<flush;
    LeaveCriticalSection(&cs_SaveInfo);
    LeaveCriticalSection(&cs_ReadyList);
    return;
  }
}
//否则，在就绪队列中寻找要撤销的进程.
if (pReadyList->head!=NULL)
{
   removeTarget=pReadyList->head;
   while(removeTarget!=NULL)
   {
     if(strcmp(name,removeTarget->name)==0)//找到要撤销的进程
     {
      if(removeTarget==pReadyList->head)//是就绪队列中的第一-个进程
      { 
        pReadyList->head=pReadyList->head->next;
        if(pReadyList->head==NULL)
            pReadyList->tail=NULL;
      }
    else
	{
		preTemp->next=removeTarget->next;
        if(removeTarget==pReadyList->tail)
           pReadyList->tail=preTemp;
    }
    if(!TerminateThread(removeTarget->hThis,0))//执行撤销进程的操作
    { 
      cout<<"Terminate thread failed! System will abort!"<<endl;
      EnterCriticalSection(&cs_SaveInfo);
      log<<"Terminate thread failed! System will abort!"<<endl;
      LeaveCriticalSection(&cs_SaveInfo);
      LeaveCriticalSection(&cs_ReadyList);
      exit(0);
    }
//撤销操作成功后的处理
    CloseHandle(removeTarget->hThis);
    returnPcbToFreeList(removeTarget);
    pReadyList->pcbNum--;
    cout<<"Process"<<removeTarget->id
        <<':'<<removeTarget->name<<"has been removed."<<endl;
    cout<<"currentreadyList is:"<<endl;
    printReadyList();
    EnterCriticalSection(&cs_SaveInfo);
    log<<"Process"<<removeTarget->id
       <<':'<<removeTarget->name<<"has been removed."<<endl;
    log<<"currentreadyList is:"<<endl;
    fprintReadyList();
    log<<flush;
    LeaveCriticalSection(&cs_SaveInfo);
    LeaveCriticalSection(&cs_ReadyList);
    return;
}
else //未找到，继续找
  {
    preTemp=removeTarget;
    removeTarget=removeTarget->next;
  }
 }
}
LeaveCriticalSection(&cs_ReadyList);
cout<<"Sorry, there's no process named "<<name<<endl;
return;
}

void fprintReadyList()
{
  pPCB tmp=NULL; 
  tmp=pReadyList->head;
  if(tmp!=NULL)
    for(int i=0;i<pReadyList->pcbNum;i++)
    {
	   log<<"--"<<tmp->id<<':'<<tmp->name<<"--";
       tmp=tmp->next;
    }
  else
      log<<"NULL";
log<<endl<<endl;
}
//向标准输出打印就绪队列信息
void printReadyList()
{
  pPCB tmp=NULL;
  tmp=pReadyList->head;
  if(tmp!=NULL)
    for(int i=0;i<pReadyList->pcbNum;i++)
    {
      cout<<"--"<<tmp->id<<':'<<tmp->name<"--";
      tmp=tmp->next;
    }
  else
      cout<<"NULL";
  cout<<endl;
}

//打印当前运行进程信息
void printCurrent()
{
  if (runPCB!=NULL)
     cout<<"Process "<<runPCB->name<<"is running..."<<endl;
  else
     cout<<"No process is running."<<endl;
  cout<<"Current readyList is:"<<endl;
  printReadyList();
}


void stopAllThreads()
{
	if(runPCB!=NULL)
	{
      TerminateThread(runPCB->hThis,0);
      CloseHandle(runPCB->hThis);
    }
//结束所有就绪队列中的线程
pPCB q,p=pReadyList->head;
while(p!=NULL)
 {
   if(!TerminateThread(p->hThis,0))
    {
     cout<<"Terminate thread failed! System will abort!"<<endl;
     exit(0);//结束程序
    }
    CloseHandle(p->hThis);
    q=p->next;
    returnPcbToFreeList(p);
    p=q;
 }
}
