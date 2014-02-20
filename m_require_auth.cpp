/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2007-2008 Dennis Friis <peavey@inspircd.org>
 *   Copyright (C) 2005-2008 Robin Burchell <robin+git@viroteck.net>
 *   Copyright (C) 2005-2006 Craig Edwards <craigedwards@brainbox.cc>
 *   Copyright (C) 2006 Oliver Lupton <oliverlupton@gmail.com>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
 
#include "inspircd.h"
#include "xline.h"
#include "bancache.h"
#include "account.h"
class ALine : public XLine{
	/** Ident mask (ident part only)
	*/
	std::string identmask;
	/** Host mask (host part only)
	*/
	std::string hostmask;

	std::string matchtext;
	public:
	ALine(time_t s_time, long d, std::string src, std::string re, std::string ident, std::string host) : XLine(s_time, d, src, re, "A"), identmask(ident), hostmask(host)
	{
		matchtext = this->identmask;
		matchtext.append("@").append(this->hostmask);
	}
	bool IsBurstable(){ return false; }
	bool isLoggedIn(User* user){
		const AccountExtItem* accountext = GetAccountExtItem();
		if (accountext && accountext->get(user))
			return true;
		return false;
	}
	bool Matches(User* u){
		if (u->exempt)
		return false;

		if (InspIRCd::Match(u->ident, this->identmask, ascii_case_insensitive_map))
		{
			if (InspIRCd::MatchCIDR(u->host, this->hostmask, ascii_case_insensitive_map) ||
				InspIRCd::MatchCIDR(u->GetIPString(), this->hostmask, ascii_case_insensitive_map))
			{
				return true;
			}
		}

		return false;
	}
	bool Matches(const std::string &s)
	{
		if (matchtext == s)
		return true;
		return false;
	}
	void Apply(User* u){
		if(u->registered==REG_ALL&&!isLoggedIn(u)){
			DefaultApply(u, "A", (this->identmask == "*") ? true : false);
		}
	}
	void DisplayExpiry(){
		ServerInstance->SNO->WriteToSnoMask('x',"Removing expired A-Line %s@%s (set by %s %ld seconds ago)",
		identmask.c_str(),hostmask.c_str(),source.c_str(),(long)(ServerInstance->Time() - this->set_time));
	}
	const char* Displayable()
	{
		return matchtext.c_str();
	}
};
class GALine : public XLine{
	/** Ident mask (ident part only)
	*/
	std::string identmask;
	/** Host mask (host part only)
	*/
	std::string hostmask;

	std::string matchtext;
	public:
	GALine(time_t s_time, long d, std::string src, std::string re, std::string ident, std::string host) : XLine(s_time, d, src, re, "GA"), identmask(ident), hostmask(host) { 
		matchtext = this->identmask;
		matchtext.append("@").append(this->hostmask);}
	bool IsBurstable(){ return true; }
	void Apply(User* u){
		if(u->registered==REG_ALL&&!isLoggedIn(u)){
			DefaultApply(u, "GA", (this->identmask == "*") ? true : false);
		}
	}
	void DisplayExpiry(){
		ServerInstance->SNO->WriteToSnoMask('x',"Removing expired GA-Line %s@%s (set by %s %ld seconds ago)",
		identmask.c_str(),hostmask.c_str(),source.c_str(),(long)(ServerInstance->Time() - this->set_time));
	}
		bool isLoggedIn(User* user){
		const AccountExtItem* accountext = GetAccountExtItem();
		if (accountext && accountext->get(user))
			return true;
		return false;
	}
	bool Matches(User* u){
		if (u->exempt)
		return false;

		if (InspIRCd::Match(u->ident, this->identmask, ascii_case_insensitive_map))
		{
			if (InspIRCd::MatchCIDR(u->host, this->hostmask, ascii_case_insensitive_map) ||
				InspIRCd::MatchCIDR(u->GetIPString(), this->hostmask, ascii_case_insensitive_map))
			{
				return true;
			}
		}

		return false;
	}
	bool Matches(const std::string &s)
	{
		if (matchtext == s)
		return true;
		return false;
	}
	const char* Displayable()
	{
		return matchtext.c_str();
	}
};
class ALineFactory : public XLineFactory
{
 public:
	ALineFactory() : XLineFactory("A") { }

	/** Generate an ALine
	 */
	ALine* Generate(time_t set_time, long duration, std::string source, std::string reason, std::string xline_specific_mask)
	{
		IdentHostPair ih = ServerInstance->XLines->IdentSplit(xline_specific_mask);
		return new ALine(set_time, duration, source, reason, ih.first, ih.second);
	}
};

class GALineFactory : public XLineFactory
{
 public:
	GALineFactory() : XLineFactory("GA") { }

	/** Generate a GALine
	 */
	GALine* Generate(time_t set_time, long duration, std::string source, std::string reason, std::string xline_specific_mask)
	{
		IdentHostPair ih = ServerInstance->XLines->IdentSplit(xline_specific_mask);
		return new GALine(set_time, duration, source, reason, ih.first, ih.second);
	}
};
class CommandALine: public Command {
	public:
	CommandALine(Module* creator) : Command(creator, "ALINE", 1, 3){
		flags_needed = 'o'; this->syntax = "<nick> [<duration> :<reason>]";
	}
	CmdResult Handle(const std::vector<std::string>& parameters, User *user){
	std::string target = parameters[0];

	if (parameters.size() >= 3)
	{
		IdentHostPair ih;
		User* find = ServerInstance->FindNick(target);
		if ((find) && (find->registered == REG_ALL))
		{
			ih.first = "*";
			ih.second = find->GetIPString();
			target = std::string("*@") + find->GetIPString();
		}
		else
			ih = ServerInstance->XLines->IdentSplit(target);

		if (ih.first.empty())
		{
			user->WriteServ("NOTICE %s :*** Target not found", user->nick.c_str());
			return CMD_FAILURE;
		}

		if (ServerInstance->HostMatchesEveryone(ih.first+"@"+ih.second,user))
			return CMD_FAILURE;

		else if (target.find('!') != std::string::npos)
		{
			user->WriteServ("NOTICE %s :*** A-Line cannot operate on nick!user@host masks",user->nick.c_str());
			return CMD_FAILURE;
		}

		long duration = ServerInstance->Duration(parameters[1].c_str());
		ALine* al = new ALine(ServerInstance->Time(), duration, user->nick.c_str(), parameters[2].c_str(), ih.first.c_str(), ih.second.c_str());
		if (ServerInstance->XLines->AddLine(al, user))
		{
			if (!duration)
			{
				ServerInstance->SNO->WriteToSnoMask('x',"%s added permanent A-line for %s: %s",user->nick.c_str(),target.c_str(), parameters[2].c_str());
			}
			else
			{
				time_t c_requires_crap = duration + ServerInstance->Time();
				std::string timestr = ServerInstance->TimeString(c_requires_crap);
				ServerInstance->SNO->WriteToSnoMask('x',"%s added timed A-line for %s, expires on %s: %s",user->nick.c_str(),target.c_str(),
						timestr.c_str(), parameters[2].c_str());
			}

			ServerInstance->XLines->ApplyLines();
		}
		else
		{
			delete al;
			user->WriteServ("NOTICE %s :*** A-Line for %s already exists",user->nick.c_str(),target.c_str());
		}

	}
	else
	{
		if (ServerInstance->XLines->DelLine(target.c_str(),"A",user))
		{
			ServerInstance->SNO->WriteToSnoMask('x',"%s removed A-line on %s",user->nick.c_str(),target.c_str());
		}
		else
		{
			user->WriteServ("NOTICE %s :*** A-line %s not found in list, try /stats a.",user->nick.c_str(),target.c_str());
		}
	}

	return CMD_SUCCESS;
	}
};

class CommandGALine: public Command {
	public:
	CommandGALine(Module* creator) : Command(creator, "GALINE", 1, 3){
		flags_needed = 'o'; this->syntax = "<nick> [<duration> :<reason>]";
	}
	CmdResult Handle(const std::vector<std::string>& parameters, User *user){
	std::string target = parameters[0];

	if (parameters.size() >= 3)
	{
		IdentHostPair ih;
		User* find = ServerInstance->FindNick(target);
		if ((find) && (find->registered == REG_ALL))
		{
			ih.first = "*";
			ih.second = find->GetIPString();
			target = std::string("*@") + find->GetIPString();
		}
		else
			ih = ServerInstance->XLines->IdentSplit(target);

		if (ih.first.empty())
		{
			user->WriteServ("NOTICE %s :*** Target not found", user->nick.c_str());
			return CMD_FAILURE;
		}

		if (ServerInstance->HostMatchesEveryone(ih.first+"@"+ih.second,user))
			return CMD_FAILURE;

		else if (target.find('!') != std::string::npos)
		{
			user->WriteServ("NOTICE %s :*** GA-Line cannot operate on nick!user@host masks",user->nick.c_str());
			return CMD_FAILURE;
		}

		long duration = ServerInstance->Duration(parameters[1].c_str());
		GALine* gal = new GALine(ServerInstance->Time(), duration, user->nick.c_str(), parameters[2].c_str(), ih.first.c_str(), ih.second.c_str());
		if (ServerInstance->XLines->AddLine(gal, user))
		{
			if (!duration)
			{
				ServerInstance->SNO->WriteToSnoMask('x',"%s added permanent GA-line for %s: %s",user->nick.c_str(),target.c_str(), parameters[2].c_str());
			}
			else
			{
				time_t c_requires_crap = duration + ServerInstance->Time();
				std::string timestr = ServerInstance->TimeString(c_requires_crap);
				ServerInstance->SNO->WriteToSnoMask('x',"%s added timed GA-line for %s, expires on %s: %s",user->nick.c_str(),target.c_str(),
						timestr.c_str(), parameters[2].c_str());
			}

			ServerInstance->XLines->ApplyLines();
		}
		else
		{
			delete gal;
			user->WriteServ("NOTICE %s :*** GA-Line for %s already exists",user->nick.c_str(),target.c_str());
		}

	}
	else
	{
		if (ServerInstance->XLines->DelLine(target.c_str(),"GA",user))
		{
			ServerInstance->SNO->WriteToSnoMask('x',"%s removed GA-line on %s",user->nick.c_str(),target.c_str());
		}
		else
		{
			user->WriteServ("NOTICE %s :*** GA-Line %s not found in list, try /stats A.",user->nick.c_str(),target.c_str());
		}
	}

	return CMD_SUCCESS;
	}
};


class ModuleRequireAuth : public Module {
	CommandALine cmd1;
	CommandGALine cmd2;
	ALineFactory fact1;
	GALineFactory fact2;
public:
	bool isLoggedIn(User* user){
		const AccountExtItem* accountext = GetAccountExtItem();
		if (accountext && accountext->get(user))
			return true;
		return false;
	}
	ModuleRequireAuth() : cmd1(this), cmd2(this){
	
	}
	void init()
	{
		ServerInstance->XLines->RegisterFactory(&fact1);
		ServerInstance->XLines->RegisterFactory(&fact2);
		ServerInstance->Modules->AddService(cmd1);
		ServerInstance->Modules->AddService(cmd2);
		Implementation eventlist[] = { I_OnUserConnect, I_OnStats };
		ServerInstance->Modules->Attach(eventlist, this, sizeof(eventlist)/sizeof(Implementation));
	}
	virtual ModResult OnStats(char symbol, User* user, string_list &out) //stats A does global lines, stats a local lines.
	{
		if (symbol != 'A' && symbol != 'a')
			return MOD_RES_PASSTHRU;
		if (symbol == 'A')
			ServerInstance->XLines->InvokeStats("GA", 210, user, out);
		else if (symbol == 'a')
			ServerInstance->XLines->InvokeStats("A", 210, user, out);
		return MOD_RES_DENY;
	}
	virtual ~ModuleRequireAuth(){
		ServerInstance->XLines->DelAll("A");
		ServerInstance->XLines->DelAll("GA");
		ServerInstance->XLines->UnregisterFactory(&fact1);
		ServerInstance->XLines->UnregisterFactory(&fact2);
	}
	virtual Version GetVersion()
	{
		return Version("Gives /aline and /galine, short for auth-lines. Users affected by these will have to use SASL to connect, while any users already connected but not identified to services will be disconnected in a similar manner to G-lines.", VF_COMMON | VF_VENDOR);
	}
	virtual void OnUserConnect(LocalUser* user){ //I'm afraid that using the normal xline methods would then result in this line being checked at the wrong time.
		if(!isLoggedIn(user)){
			XLine *locallines = ServerInstance->XLines->MatchesLine("A", user);
			XLine *globallines = ServerInstance->XLines->MatchesLine("GA", user);
			if(locallines){//If there are lines matching this user
				user->WriteServ("NOTICE %s :*** NOTICE -- You need to identify via SASL to use this server (your host is A-Lined).");
				ServerInstance->Users->QuitUser(user, "A-Lined: "+locallines->reason);
			}
			else if(globallines){
				user->WriteServ("NOTICE %s :*** NOTICE -- You need to identify via SASL to use this server (your host is GA-Lined).");
				ServerInstance->Users->QuitUser(user, "GA-Lined: "+globallines->reason);
			}	
		}
	}
};

MODULE_INIT(ModuleRequireAuth)
