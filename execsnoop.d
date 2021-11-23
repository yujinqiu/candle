#!/usr/sbin/dtrace -s
/*
** execsnoop.d - snoop process execution as it occurs.
**		 Written in DTrace (Solaris 10 build 51).
**
** NOTE: This version is deprecated. See "execsnoop",
** 	http://www.brendangregg.com/dtrace.html
**
** 27-Mar-2004, ver 0.60
**
**
** USAGE:	./execsnoop.d
**
**	Different styles of output can be selected by changing
**	the "PFORMAT" variable below.
** 	
** FIELDS:
**		UID	user ID
**		PID	process ID
**		PPID	parent process ID
**		CMD	command (full arguments)
**		TIME	end timestamp, us
**		STIME 	start timestamp, us
**
** SEE ALSO: BSM auditing
**
** Standard Disclaimer: This is freeware, use at your own risk.
**
** 27-Mar-2004	Brendan Gregg	Created this.
**
*/

inline int PFORMAT = 1;
/*			1 - Default output
**			2 - Timestamp output (includes TIME)
**			3 - Everything, space delimited (for spreadsheets)
*/

#pragma D option quiet


/*
**  Print header
*/
dtrace:::BEGIN /PFORMAT == 1/ { 
	printf("%5s %5s %5s %s\n","UID","PID","PPID","CMD");
}
dtrace:::BEGIN /PFORMAT == 2/ { 
	printf("%-14s %5s %5s %5s %s\n",
	 "TIME","UID","PID","PPID","CMD");
}
dtrace:::BEGIN /PFORMAT == 3/ { 
	printf("%s %s %s %s %s %s\n",
	 "STIME","TIME","UID","PID","PPID","CMD");
}


/*
**  Main
*/
syscall::execve:entry
{
	/*
	**  Store values
	*/
	self->uid = curpsinfo->pr_euid;
	self->pid = pid;
	self->ppid = curpsinfo->pr_ppid;
	self->args = (char *)curpsinfo->pr_psargs;
	self->time = timestamp;
}


/*
**  Print output
*/
syscall::execve:return
/PFORMAT == 1 && arg0 == 0/ 
{
	printf("%5d %5d %5d %s\n",
	 self->uid,self->pid,self->ppid,stringof(self->args));
}
syscall::execve:return
/PFORMAT == 2 && arg0 == 0/ 
{
	printf("%-14d %5d %5d %5d %s\n",
	 timestamp/1000,self->uid,self->pid,
	 self->ppid,stringof(self->args));
}
syscall::execve:return
/PFORMAT == 3 && arg0 == 0/ 
{
	printf("%d %d %d %d %d %s\n",
	 self->time/1000,timestamp/1000,self->uid,self->pid,
	 self->ppid,stringof(self->args));
}


/*
**  Cleanup
*/
syscall::execve:return {
	self->time = 0;
	self->uid = 0;
	self->pid = 0;
	self->ppid = 0;
	self->args = 0;
}
