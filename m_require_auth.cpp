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
#include "modules/account.h"
class ALine : public XLine{
	ALine(time_t s_time, long d, const std::string& src, const std::string& re, std::string& ip) : XLine(s_time, d, src, re, "A") { }
	bool IsBurstable(){ return false; }
	bool isLoggedIn(User* user){
		const AccountExtItem* accountext = GetAccountExtItem();
		if (accountext && accounttext->get(user))
			return true;
		return false;
	}
	bool Matches(const std::string &str){
		return (InspIRCd::MatchCIDR(str.c_str(), matchtext));
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
		return ipaddr.c_str();
	}
};
class GALine : public ALine{
	GALine(time_t s_time, long d, const std::string& src, const std::string& re, std::string& ip) : XLine(s_time, d, src, re, "GA") { }
	bool IsBurstable()}{ return true; }
	void Apply(User* u){
		if(u->registered==REG_ALL&&!isLoggedIn(u)){
			DefaultApply(u, "GA", (this->identmask == "*") ? true : false);
		}
	}
	void DisplayExpiry(){
		ServerInstance->SNO->WriteToSnoMask('x',"Removing expired GA-Line %s@%s (set by %s %ld seconds ago)",
		identmask.c_str(),hostmask.c_str(),source.c_str(),(long)(ServerInstance->Time() - this->set_time));
	}
};
class ALineFactory : public XLineFactory
{
 public:
	ALineFactory() : XLineFactory("A") { }

	/** Generate a GALine
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

	/** Generate an ALine
	 */
	GALine* Generate(time_t set_time, long duration, std::string source, std::string reason, std::string xline_specific_mask)
	{
		IdentHostPair ih = ServerInstance->XLines->IdentSplit(xline_specific_mask);
		return new GALine(set_time, duration, source, reason, ih.first, ih.second);
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
		if (accountext && accounttext->get(user))
			return true;
		return false;
	}
	ModuleGZline() : cmd1(this), cmd2(this){
	
	}
	void init()
	{
		ServerInstance->XLines->RegisterFactory(&fact1);
		ServerInstance->XLines->RegisterFactory(&fact1);
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
	virtual ModResult OnUserConnect(LocalUser* user){ //I'm afraid that using the normal xline methods would then result in this line being checked at the wrong time.
		if(!isLoggedIn(user){
			XLine *locallines = ServerInstance->Xlines>MatchesLine("A", user);
			XLine *globallines = ServerInstance->Xlines>MatchesLine("GA", user);
			if(locallines||globallines){//If there are lines matching this user
				//user->WriteNumeric(477, user->name+" You need to identify to services via SASL in order to use this server (your host is A-Lined and/or GA-Lined).");
				user->WriteNotice("*** NOTICE -- You need to identify via SASL to use this server (your host is A-Lined and/or GA-Lined)."); /*Need to decide between either a numeric or a notice*/
				return MOD_RES_DENY;
			}
		}
		return MOD_RES_PASSTHRU;
	}
};

MODULE_INIT(ModuleRequireAuth)

