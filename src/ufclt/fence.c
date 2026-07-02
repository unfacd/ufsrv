/*
** Copyright (c) 1998-2015 Ayman Akt
**
** This file is part of the IRCIT (c) source distribution.
** See the COPYING file for terms of use and conditions.
*/

#include <main.h>
#include <uflib/adt/adt_hashtable.h>
#include <ufsrvmsg_core/fence/fence.h>
#include <ufsrvmsg_core/location/location_type.h>
#include <pthread.h>
#include <list.h>

//hashtable for mapping fence ids (base and user)
//static HashTable FenceRegistryIdHashTable;

//hashtable for mapping fence canonical names (base and user)
//static HashTable FenceRegistryCanonicalNameHashTable;

//user created fences
//static List MasterFenceRegistry;
//static List *const master_fence_registry_ptr=&MasterFenceRegistry;
//static pthread_rwlock_t       master_user_fence_rwlock;
//static pthread_rwlockattr_t    master_user_fence_attr;


#define FENCE_EVENTS_RDLOCK(x) \
		{\
		 int lock_state = pthread_rwlock_rdlock(&(f_ptr->fence_events.rwlock));\
		 if (lock_state==0) syslog(LOG_INFO, "(x) (pid='%lu'): SUCCESS: ACQUIRED READ lock for fence events...", pthread_self());\
		 else 	syslog(LOG_INFO, "(x) (pid='%lu'): ERROR: COULD NOT ACQUIRE READ LOCK for fence events: errno: '%d'", pthread_self(), errno);\
		}

#define FENCE_EVENTS_RWLOCK(x) \
		{\
		 int lock_state = pthread_rwlock_wrlock(&(f_ptr->fence_events.rwlock));\
		 if (lock_state==0) syslog(LOG_INFO, "(x) (pid='%lu'): SUCCESS: ACQUIRED WRITE/READ lock for fence events...", pthread_self());\
		 else 	syslog(LOG_INFO, "(x) (pid='%lu'): ERROR: COULD NOT ACQUIRE WRITE/READ lock for fence events: errno: '%d'",  pthread_self(), errno);\
		}

#define FENCE_EVENTS_RWUNLOCK(x) \
		{\
		int lock_state = pthread_rwlock_unlock(&(f_ptr->fence_events.rwlock));\
		 if (lock_state==0) syslog(LOG_INFO, "(x) (pid='%lu'): SUCCESS: RELEASED WRITE/READ lock for fence events...", pthread_self());\
		 else 	syslog(LOG_INFO, "(x) (pid='%lu'): ERROR: COULD NOT RELEASE WRITE/READ lock for fence events: errno: '%d'",  pthread_self(), errno);\
		}

//static entity at the base of the Base Fence Registry.
Fence *broadcast_fence_ptr;

inline static Fence *
_f_FindFenceInUserListByID (const List *const, const unsigned long);
inline static Fence *
_f_FindFenceInUserListByCanonicalName (const List *const lst_ptr, const char *fence_canonical_name);
static unsigned
_f_CheckIntraBaseFencesAndAdd (Session *, const LocationDescription *, unsigned);
static unsigned
_f_BaseLocValid (User *, const char *);
static char *
_f_MakeCanonicalFenceName(LocationDescription *, const char *);

static UFSRVResult *
_f_UserAllowedToJoinFence(SessionService *, Fence *, int);

static void SummariseFenceConfiguration (List *, const char *);

static void *
_m_AddMessageToFenceQueue (SessionService *, Fence *, Message *const);
static Fence *
_f_CreateBaseFence (void);
static Fence *
_f_CreateUserFence (void);

static int _f_DestructUserFence (Session *, Fence *);
static void * _f_DestructFenceMessageQueue (Fence *);
static Fence *_f_RemoveUserFromUserFenceAndUnlinkUser(Fence *, SessionService *);
static Fence *_f_RemoveUserFromBaseFenceAndUnlinkUser(Fence *, SessionService *);
static Fence *_f_RemoveUserFromBaseFence (SessionService *, Fence *);//unsigned long);
static Fence *_f_RemoveUserFromUserFence (SessionService *ss_ptr, Fence *);//unsigned long);
static Fence *_f_FindFenceContainingBaseloc (const List *, const char *);
inline static unsigned
_f_CrossCheckUserInFenceAndFenceInUser(Fence *, SessionService *);


//-----------------------------------------------------------

#define CHECK_SESSION_POINTER_FOR_NULL(x) \
	if (sesn_ptr==NULL)\
	{\
		syslog(LOG_ERR, "!! (x) was passed NULL Session *");\
		return NULL;\
	}
#define CHECK_SESSION_FOR_NULL(x, y) \
		if (sesn_ptr==NULL)\
		{\
			syslog(LOG_ERR, "x: ERROR: NULL Session *");\
			return y;\
		}
#define CHECK_LOCATION_DESCRIPTION_FOR_NULL(x, y) \
	if (ld_ptr==NULL)\
	{\
		syslog(LOG_ERR, "x: ERROR: was passed NULL LocationDescription *");\
		return y;\
	}
#define CHECK_SESSION_SERVICE_FOR_NULL(x, y) \
		if (ss_ptr==NULL)\
		{\
			syslog(LOG_ERR, "!! (x) was passed NULL SessionService *");\
			return y;\
		}
#define CHECK_FENCE_FOR_NULL(x) \
		if (f_ptr==NULL)\
		{\
			syslog(LOG_ERR, "!! (x) was passed NULL Fence *");\
			return NULL;\
		}
#define CHECK_LIST_POINTER_FOR_NULL(x) \
	if (lst_ptr==NULL)\
	{\
		syslog(LOG_ERR, "!! (x) was passed NULL List *");\
		return NULL;\
	}
#define CHECK_CANONICAL_NAME_FOR_NULL_POINTER(x) \
	if(fence_canonical_name==NULL)\
	{\
		syslog(LOG_ERR, "!! (x) was passed NULL char *");\
		return NULL;\
	}


inline unsigned long
GenerateFenceEventId (Fence *f_ptr)
{
	if (f_ptr)
	{
		FENCE_EVENTS_RWLOCK(GenerateFenceEventId);
		volatile unsigned long fence_event_counter=++f_ptr->fence_events.event_counter;
		FENCE_EVENTS_RWUNLOCK(GenerateFenceEventId);

		return fence_event_counter;
	}

	return 0;

}


unsigned long
GetFenceEventId (Fence *f_ptr)
{
	if (f_ptr)
	{
		FENCE_EVENTS_RDLOCK(GenerateFenceEventId);
		volatile unsigned long fence_event_counter=f_ptr->fence_events.event_counter;
		FENCE_EVENTS_RWUNLOCK(GenerateFenceEventId);

		return fence_event_counter;
	}

	return 0;

}


//TODO: dynamic string allocation: user must free
//TODO: we should hash this value
 //produces final fully qualified user fence name, incorporating all known location information
  //for USER FENCE only, but it dove tails with _f_CheckIntraBaseFencesAndAdd which handles BaseFences
  //if userfence_banner is null it only create baseloc_prefix value
static char *
_f_MakeCanonicalFenceName(LocationDescription *ld_ptr, const char *userfence_banner)
{

	CHECK_LOCATION_DESCRIPTION_FOR_NULL(ld_ptr, NULL);

	char *canonical_name=NULL;

	if (ld_ptr->country&&strlen(ld_ptr->country)>0)
	{
		if (ld_ptr->admin_area&&strlen(ld_ptr->admin_area)>0)
		{//country:admin_area
			//ideal case: country:admin_area


			if (ld_ptr->locality&&strlen(ld_ptr->locality)>0)
			{
				//ideal case
				if (userfence_banner) asprintf(&canonical_name, "%s:%s:%s:%s", ld_ptr->country, ld_ptr->admin_area, ld_ptr->locality, userfence_banner);
				else asprintf(&canonical_name, "%s:%s:%s", ld_ptr->country, ld_ptr->admin_area, ld_ptr->locality);
			}
			else
			{//country:admin_area:NO_locality

				//second ideal
				if (userfence_banner)	asprintf(&canonical_name, "%s:%s::%s", ld_ptr->country, ld_ptr->admin_area, userfence_banner);
				else asprintf(&canonical_name, "%s:%s::", ld_ptr->country, ld_ptr->admin_area);
			}
		}
		else
		{// country:no_admin_area
			//allow for country::locality type
			if (ld_ptr->locality&&strlen(ld_ptr->locality)>0)
			{
				if (userfence_banner)	asprintf(&canonical_name, "%s::%s:%s", ld_ptr->country, ld_ptr->locality, userfence_banner);
				else asprintf(&canonical_name, "%s::%s", ld_ptr->country, ld_ptr->locality);
				syslog(LOG_INFO, "MakeCanonicalFenceName: MISSING ADMIN AREA for canonical name.");
			}
			else
			{//country:NO_admin_ara:NO_locality
				//allow for country::
				if (userfence_banner)	asprintf(&canonical_name, "%s:::%s", ld_ptr->country, userfence_banner);
				else 	asprintf(&canonical_name, "%s::", ld_ptr->country);
				syslog(LOG_INFO, "MakeCanonicalFenceName: MISSING ADMIN AREA & MISSING LOCALITY for canonical name.");
			}
		}
	}
	else//no country: no go
	if (ld_ptr->admin_area&&strlen(ld_ptr->admin_area)>0)
	{
		//dont allow for "empty:admin:locality type"

		syslog(LOG_ERR, "MakeCanonicalFenceName: WILL NOT create a canonical for NoCountryDefined: '%s'", userfence_banner);

	}

	if (canonical_name) syslog(LOG_INFO, "MakeCanonicalFenceName: produced: '%s'", canonical_name);


	return canonical_name;

}


#define PERSIST_REGISTER_BASEFENCE \
		(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "HMSET FBF:%lu cname '%s' bname '%s' when %lu lng %f lat %f",\
									f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_location.display_banner_name, f_ptr->when,\
									f_ptr->fence_location.fence_location.longitude, f_ptr->fence_location.fence_location.latitude)

#define PERSIST_REMOVE_BASEFENCE \
		(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "DEL FBF:%lu",f_ptr->fence_id)

#define PERSIST_REGISTER_USERFENCE \
		(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "HMSET FUF:%lu cname '%s' bname '%s' when %lu lng %f lat %f",\
									f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_location.display_banner_name, f_ptr->when,\
									f_ptr->fence_location.fence_location.longitude, f_ptr->fence_location.fence_location.latitude)
#define PERSIST_REMOVE_USERFENCE \
		redis_ptr=(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "DEL FUF:%lu",f_ptr->fence_id);\
		freeReplyObject(redis_ptr)

//
//create_flg is ignored under this implementation
//Works for Network BaseFences, no user defined fence name, as opposed to MakeFenceByCanonicalName
//unrolls the canonical name and creates BaseFences for the locations bits that are known
//follows the naming rules used in MakeCanonicalFenceName
//four permutaions which match the four patterns produced in MakeCanonicalFenceName
//LocationDescription * reflects user, not fence
//
#if 0
static unsigned
_f_CheckIntraBaseFencesAndAdd (Session *sesn_ptr, const LocationDescription *ld_ptr, unsigned add_flag)
{
	CHECK_LOCATION_DESCRIPTION_FOR_NULL(_f_CheckIntraBaseFencesAndAdd, -1);

	unsigned int counter=0;
	//Session *sesn_ptr=container_of(ss_ptr, Session, sservice);

	if (ld_ptr->country&&strlen(ld_ptr->country)>0)
	{
		Fence *f_ptr=NULL;
		char *cn_country=NULL;

		asprintf(&cn_country, "%s::", ld_ptr->country);
		//country
		if (!(FindBaseFenceByCanonicalName(cn_country)))

		{
			f_ptr=_f_CreateBaseFence();
			counter++;
			f_ptr->fence_location.display_banner_name=mystrdup(ld_ptr->country);
			f_ptr->fence_location.canonical_name=cn_country;
			f_ptr->fence_location.base_location=cn_country;//TODO: dont deallocate

			AddToHash(&FenceRegistryCanonicalNameHashTable, f_ptr);
			AddToHash(&FenceRegistryIdHashTable, f_ptr);

			GeocodeLocation (sesn_ptr, &f_ptr->fence_location.fence_location, f_ptr->fence_location.display_banner_name);

			(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "HMSET FBF:%lu cname '%s' bname '%s' when %lu lng %f lat %f",\
				f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_location.display_banner_name, f_ptr->when,\
				f_ptr->fence_location.fence_location.longitude, f_ptr->fence_location.fence_location.latitude);

			//(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "ZADD BF_%s 0 %s", f_ptr->fence_location.canonical_name, f_ptr->fence_location.display_banner_name);
			(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "ZADD BF 0 %s", f_ptr->fence_location.canonical_name);
		}

		if (ld_ptr->admin_area&&strlen(ld_ptr->admin_area)>0)
		{//country:admin_area
			char *cn_country_admin_area=NULL;

			asprintf(&cn_country_admin_area, "%s:%s:", ld_ptr->country, ld_ptr->admin_area);

			if (!(FindBaseFenceByCanonicalName(cn_country_admin_area)))
			{
				f_ptr=_f_CreateBaseFence();
				f_ptr->fence_location.display_banner_name=mystrdup(ld_ptr->admin_area);
				f_ptr->fence_location.canonical_name=cn_country_admin_area;
				f_ptr->fence_location.base_location=cn_country_admin_area;

				AddToHash(&FenceRegistryCanonicalNameHashTable, f_ptr);
				AddToHash(&FenceRegistryIdHashTable, f_ptr);
				//GeocodeLocation (ss_ptr, ld_ptr, f_ptr->fence_location.canonical_name);

				char *s=NULL;
				asprintf(&s, "%s,%s", ld_ptr->country, f_ptr->fence_location.display_banner_name);
				GeocodeLocation (sesn_ptr, &f_ptr->fence_location.fence_location, s);free(s);

				(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "HMSET FBF:%lu cname '%s' bname '%s' when %lu lng %f lat %f",\
					f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_location.display_banner_name, f_ptr->when,\
					f_ptr->fence_location.fence_location.longitude, f_ptr->fence_location.fence_location.latitude);
				(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "ZADD BF 0 %s", f_ptr->fence_location.canonical_name);
				counter++;
				//free(cn_country_admin_area);
			}

				if (ld_ptr->locality&&strlen(ld_ptr->locality)>0)//ideal case: all components defined
				{//country:admin_area:locality
					char *cn_country_admin_area_locality=NULL;
					asprintf(&cn_country_admin_area_locality, "%s:%s:%s", ld_ptr->country, ld_ptr->admin_area, ld_ptr->locality);
					if (!(FindBaseFenceByCanonicalName(cn_country_admin_area_locality)))
					{
						f_ptr=_f_CreateBaseFence();
						f_ptr->fence_location.display_banner_name=mystrdup(ld_ptr->locality);
						f_ptr->fence_location.canonical_name=cn_country_admin_area_locality;
						f_ptr->fence_location.base_location=cn_country_admin_area_locality;

						AddToHash(&FenceRegistryCanonicalNameHashTable, f_ptr);
						AddToHash(&FenceRegistryIdHashTable, f_ptr);

						char *s=NULL;
						asprintf(&s, "%s,%s,%s", ld_ptr->country, ld_ptr->admin_area, ld_ptr->locality);
						GeocodeLocation (sesn_ptr, &f_ptr->fence_location.fence_location, s); free(s);

						(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "HMSET FBF:%lu cname '%s' bname '%s' when %lu lng %f lat %f",\
							f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_location.display_banner_name, f_ptr->when,\
							f_ptr->fence_location.fence_location.longitude, f_ptr->fence_location.fence_location.latitude);
						(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "ZADD BF 0 %s", f_ptr->fence_location.canonical_name);
						counter++;
						//free(cn_country_admin_area_locality);
					}
				}
				else
				{//country:admin_area:NO_locality
				//circular logic this is covered in the parent case
				}
		}
		else
		{//country:NO_admin_area
			if (ld_ptr->locality&&strlen(ld_ptr->locality)>0)//TODO: we should not allow this at client side
			{//country:NO_admin_area:locality
				char *cn_s=NULL;
				asprintf(&cn_s, "%s::%s", ld_ptr->country, ld_ptr->locality);//note display name collision with above
				if (!(FindBaseFenceByCanonicalName(cn_s)))
				{
					f_ptr=_f_CreateBaseFence();
					f_ptr->fence_location.display_banner_name=mystrdup(ld_ptr->locality);
					f_ptr->fence_location.canonical_name=cn_s;//happens in AddBaseFence
					f_ptr->fence_location.base_location=cn_s;

					AddToHash(&FenceRegistryCanonicalNameHashTable, f_ptr);
					AddToHash(&FenceRegistryIdHashTable, f_ptr);

					char *s=NULL;
					asprintf(&s, "%s,%s", ld_ptr->country, ld_ptr->locality);
					GeocodeLocation (sesn_ptr, &f_ptr->fence_location.fence_location, s); free(s);

					(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "HMSET FBF:%lu cname '%s' bname '%s' when %lu lng %f lat %f",\
						f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_location.display_banner_name, f_ptr->when,\
						f_ptr->fence_location.fence_location.longitude, f_ptr->fence_location.fence_location.latitude);
					(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "ZADD BF 0 %s", f_ptr->fence_location.canonical_name);
					counter++;
					//free(cn_s);
				}
			}
			else
			{
				//country_NO_admin_area:NO_locality
				//circular logic back top most case
				//char *cn_s=asprintf("%s::", ld_ptr->country);
			}
		}
	}//no country no go
	else
	//if (ld_ptr->admin_area&&strlen(ld_ptr->admin_area)>0)//no country no go
	{
		//dont allow for "nocountry:admin:locality type"
		syslog(LOG_ERR, "CheckIntermediateBaseFences: WILL NOT create a BaseFence for NoCountryDefined");

	}

	return counter;

}
#endif
//------------------ MESSAGE QUEUE ROUTINES --------------------------

void *
RegisterFenceMessage (SessionService *ss_ptr, Fence *f_ptr, Message *const msg_ptr)

{

	return (_m_AddMessageToFenceQueue (ss_ptr, f_ptr, msg_ptr));

}

#define ADD_MESSAGE_TO_QUEUE \
		qe_ptr=AddQueue(&FENCE_MESSAGE_QUEUE(f_ptr));\
		qe_ptr->whatever=(void *)msg_ptr;\
		syslog(LOG_DEBUG, "%s: Added message to Fence(%s) queue(%lu entries). Message: '%s'",__func__\
			f_ptr->fence_location.display_banner_name, FENCE_MESSAGE_QUEUE(f_ptr).nEntries, msg_ptr->msg);


//Message previously allocated we are just holding a pointer
static void *
_m_AddMessageToFenceQueue (SessionService *ss_ptr, Fence *f_ptr, Message *msg_ptr)
{

	QueueEntry *qe_ptr=NULL;

	if (FENCE_MESSAGE_QUEUE(f_ptr).nEntries<10)//TODO: define teh constat somewhere else
	{
		ADD_MESSAGE_TO_QUEUE;
	}
	else
	{
		QueueEntry *qe_ptr2=NULL;

		qe_ptr=deQueue(&FENCE_MESSAGE_QUEUE(f_ptr));
		syslog(LOG_INFO, "_m_AddMessageToFenceQueue: FenceQueue reached max size(%lu entries): popping off the oldest message: '%s'", FENCE_MESSAGE_QUEUE(f_ptr).nEntries, MESSAGE_IN_QUEUE(qe_ptr)->msg);
		free(qe_ptr);

		ADD_MESSAGE_TO_QUEUE;
	}

	RETURN_RESULT_NOOP(ss_ptr);

}

//called from DestructFence as part of deep destruction process
//as part of Fence destruction we also clear the Queue. Actual object stored in "whatever" i.e. Message
//is destroyed somewhere else as it is not instantiated in this module
//Dont read the stuff inside eptr->whatever we cannot be certain if it has been freed already
static void
* _f_DestructFenceMessageQueue (Fence *f_ptr)

{
	if(FENCE_MESSAGE_QUEUE(f_ptr).nEntries==0)
	{
		syslog(LOG_INFO, "DestroyFenceMessageQueue: COULD NOT destruct user message Queue for Fence: '%s'. Total entries: '%lu'",
					f_ptr->fence_location.display_banner_name, FENCE_MESSAGE_QUEUE(f_ptr).nEntries);

		return NULL;
	}

	syslog(LOG_INFO, "DestroyFenceMessageQueue: Destroying user message Queue for Fence: '%s'. Total entries: '%lu'",
			f_ptr->fence_location.display_banner_name, FENCE_MESSAGE_QUEUE(f_ptr).nEntries);

	QueueEntry *qe_ptr=NULL;
	while (FENCE_MESSAGE_QUEUE(f_ptr).nEntries!=0)
	{
		//1)Retrieve carrier object
		qe_ptr=deQueue(&FENCE_MESSAGE_QUEUE(f_ptr));

		//2)destruct carrier object
		free(qe_ptr);
	}

	return NULL;//RETURN_RESULT_NOOP(ss_ptr);

}


//-------------------------- END OF MESSAGE QUEUE ROUTINES ------

//-------------------------- ADD ROUTINES ------------------------

#if 0
//everybody gets added to the master list
//a reference is kept in the user's SessionService as well
//this generic list insertion routine and works across BAse and User fence registeries
//wrapper for BAse and User uses are used
//AddBaseFence->_f_AddBaseFence(master_base_fence)->_f_CreateFence(List)
//No check for fence name duplication is checked this should be performed upstream in the call chain

static Fence *_f_CreateFence (List *lst_ptr)

   {
  	ListEntry *eptr=NULL;
  	Fence *f_ptr=NULL;

  	if (lst_ptr)
  	{
  	   xmalloc(f_ptr, (sizeof(Fence)));
  	   memset (f_ptr, 0, sizeof(Fence));

  	   if ((eptr=AddtoList(lst_ptr)))
  		{
  		//load actual object in container ListEntry
  		 eptr->whatever=f_ptr;

  		return (Fence *)f_ptr;
  		}
  		else
  	 	{
  			syslog(LOG_ERR, "!! Structural problem: Unable to create Fence");
  			free(f_ptr);

  		    return ((Fence *)NULL);
  		 }
  	}
  	else
  	{
  		syslog(LOG_ERR, "!! Structural problem: one or more of CreateFence input ptr is NULL");
  		return ((Fence *)NULL);
  	}

   }  /**/

#endif

#define COMMON_FENCE_ADD_ASSIGNMENTS \
		//f_ptr->fence_id=GenerateRandomNumber();\
		f_ptr->when=time(NULL)

//only one local base fence per user, can have many remote ones
//no hash is created here for base fences, done in" _f_CheckIntraBaseFenceAndAdd()
static Fence *
_f_CreateBaseFence (void)
{
	 Fence *f_ptr;

	 f_ptr=xmalloc(f_ptr, (sizeof(Fence)));
	 memset (f_ptr, 0, sizeof(Fence));

	 pthread_rwlockattr_init(&(f_ptr->fence_events.rwattr));
	 int rc=pthread_rwlock_init(&(f_ptr->fence_events.rwlock), &(f_ptr->fence_events.rwattr));//==0 on success

	 if (rc==0)
	 {
		COMMON_FENCE_ADD_ASSIGNMENTS;
		F_ATTR_SET(f_ptr->attrs, F_ATTR_BASEFENCE);
		F_ATTR_SET(f_ptr->attrs, F_ATTR_BASEFENCE_LOCAL);

		syslog(LOG_DEBUG, "%s (b:%u,bl:%u): SUCCESS: ADDED BASE FENCE (bid='%lu). GLOBAL Fence count(not counting this)='%lu'...", __func__,
						  F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_USERFENCE)?0:1,
								  F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE_LOCAL)?1:0, f_ptr->fence_id);//  FenceRegistryCanonicalNameHashTable.fNumEntries);

		return f_ptr;
	 }
	 else
	 {
		char error_str[250];
		strerror_r(errno, error_str, 250);

		syslog(LOG_ERR, "%s: ERROR: (errno: '%d' str='%s'): COULD NOT INITIALISE fence_events.rwlock: error: '%s'...", __func__, errno, error_str);
		free (f_ptr);
	 }

	 return NULL;

}


static Fence *
_f_CreateUserFence (void)
{
	Fence *f_ptr;

	f_ptr=xmalloc(f_ptr, (sizeof(Fence)));
	memset (f_ptr, 0, sizeof(Fence));

	pthread_rwlockattr_init(&(f_ptr->fence_events.rwattr));
	int rc=pthread_rwlock_init(&(f_ptr->fence_events.rwlock), &(f_ptr->fence_events.rwattr));//==0 on success

	if (rc==0)
	{
		COMMON_FENCE_ADD_ASSIGNMENTS;
		F_ATTR_SET(f_ptr->attrs, F_ATTR_USERFENCE);
#ifdef __UF_TESTING
		syslog(LOG_INFO, "%s (type:'%u' 1=user): SUCCESS: ADDED USER FENCE (bid='%lu). GLOBAL Fence count(not counting this)='%lu'...", __func__,
			  F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE)?0:1, f_ptr->fence_id);//,  FenceRegistryCanonicalNameHashTable.fNumEntries);
#endif

		return f_ptr;
	}
	else
	{
		char error_str[250];
		strerror_r(errno, error_str, 250);

		syslog(LOG_ERR, "%s: ERROR: (errno: '%d' str='%s'): COULD NOT INITIALISE fence_events.rwlock: error: '%s'...", __func__, errno, error_str);
		free (f_ptr);
	}
	return NULL;

}


//
//we have the fence just add the user to it and link up as necessary
//IMPORTANT NO integrity check is done if user is already in Fence. This should be done in the calling environment
//locking required at a higher level
//
Fence *
AddUserToExistingFenceAndLinkToUser(Fence *f_ptr, SessionService *ss_ptr)
{
	CHECK_SESSION_SERVICE_FOR_NULL(AddUserToBaseFenceAndLinkToUser, NULL);
	CHECK_FENCE_FOR_NULL(AddUserToBaseFenceAndLinkToUser);

	//2)link this Fence to User's List of Fences
	//AddFenceToSession (container_of(ss_ptr, Session, sservice), f_ptr);//locks Session
	AddThisToList (&ss_ptr->session_user_fence_list, f_ptr);

	//3)add this ServiceSession (User) to Fence's List
	AddThisToList (&f_ptr->fence_user_sessions_list, ss_ptr);

	//now reference this  _local_ BaseFence in the User datatype
	//TODO: this is flawed
	///ss_ptr->user.user_details.base_fence_local=f_ptr;

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s: SUCCESS: LINKED (uid='%lu' fence_count='%lu') to (bid='%lu' user_coutnt='%lu')...", __func__, ss_ptr->user.user_details.user_id, ss_ptr->session_user_fence_list.nEntries, f_ptr->fence_id, f_ptr->fence_user_sessions_list.nEntries);
#endif

	return f_ptr;

}


#define USER_LONGITUDE \
		ss_ptr->user.user_details.user_location_initialised?ss_ptr->user.user_details.user_location.longitude:\
		  				 (ss_ptr->user.user_details.user_location_by_server_initialised?ss_ptr->user.user_details.user_location_by_server.longitude:0.0)
#define USER_LATITUDE \
   		ss_ptr->user.user_details.user_location_initialised?ss_ptr->user.user_details.user_location.latitude:\
   		  				 (ss_ptr->user.user_details.user_location_by_server_initialised?ss_ptr->user.user_details.user_location_by_server.latitude:0.0)

//
//Create brand new user fence and fully link it to user. contrast with AddtoExisting Fence
//IMPORTANT: if using userfence_canonical_name_in must be previously malloced in the calling environment
//future version should allow passing in of LocationDescription object
//No need for locking
//
Fence *
CreateUserFenceAndLinkToUser (SessionService *ss_ptr, const char *fence_banner, char *userfence_canonical_name_in)
{
	Fence *f_ptr;

	CHECK_SESSION_SERVICE_FOR_NULL(CreateFenceAndLinkToUser, NULL);
	//CHECK_CANONICAL_NAME_FOR_NULL_POINTER(CreateFenceAndLinkToUser);

	if (!fence_banner || (strlen(fence_banner)==0))
	{
		syslog (LOG_DEBUG, "%s: ERROR: INVALID fence_banner parameter", __func__);

		return NULL;
	}

 	Session *sesn_ptr=container_of(ss_ptr, Session, sservice);

 	//1)add to Master Fence Registry (User)
 	  if ((f_ptr=_f_CreateUserFence()))
 	  {
 		 //2)link this Fence to User's List of Fences
 		  AddThisToList (&(ss_ptr->session_user_fence_list), f_ptr);//session locked at higher level
// 		  AddFenceToSession (container_of(ss_ptr, Session, sservice), f_ptr);//locks Session

 		 //3)add this ServiceSession (User) to Fence's List
 		  //no need to lock f_ptr as it is not visible
 		  //DONT DO THIS HERE FOR CLIENT as it u_ptr needs to come from GLOBAL CLIENT LIST for the client ss_ptr->useris the actual owner
 		  //AddThisToList (&f_ptr->fence_user_sessions_list, &(ss_ptr->user));

 		  //4)fill the fields with values so we have a complete description of the fence
 		 char *userfence_canonical_name=NULL;
 		 if (userfence_canonical_name_in)
 		 {
 			userfence_canonical_name=userfence_canonical_name_in;//previously dynamically allocated and safe to use
 		 }
 		 else
 		 {
 			 LocationDescription *ld_ptr=ss_ptr->user.user_details.user_location_initialised?
 				 (&ss_ptr->user.user_details.user_location):(&ss_ptr->user.user_details.user_location_by_server);
 			 userfence_canonical_name=_f_MakeCanonicalFenceName(ld_ptr, fence_banner);//&(ss_ptr->user.user_details.user_location), fence_banner);
 		 }

 		 //we should not need to strdup if we invoked MakeCanonicalFenceName
 		 f_ptr->fence_location.canonical_name=userfence_canonical_name;
 		 f_ptr->fence_location.display_banner_name=mystrdup(fence_banner);
 		 f_ptr->fence_owner_id=ss_ptr->user.user_details.user_id;
 		 {
			 int len=strlen(f_ptr->fence_location.canonical_name);//xxx:yyy:zzz
			 int len2=strlen(f_ptr->fence_location.display_banner_name);//zzz
			 int len3=len-len2;//11-3=8

			 f_ptr->fence_location.base_location=malloc(len3+1);//9 extra for null
			 memcpy(f_ptr->fence_location.base_location, f_ptr->fence_location.canonical_name, len3);
			 *(f_ptr->fence_location.base_location+(len3+1))=0;

 #ifdef __UF_FULLDEBUG
			 syslog(LOG_DEBUG, "%s: BASELOC IS: '%s'", __func__, f_ptr->fence_location.base_location);
#endif
 		 }
 		 f_ptr->fence_location.fence_location.latitude=USER_LATITUDE;
 		 f_ptr->fence_location.fence_location.longitude=USER_LONGITUDE;
#if 0
 		//AddToHash(&FenceRegistryCanonicalNameHashTable, f_ptr);
 		//AddToHash(&FenceRegistryIdHashTable, f_ptr);

 		redisReply *redis_ptr=(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "ZADD BF 0 %s", f_ptr->fence_location.canonical_name);
 		freeReplyObject(redis_ptr);

 		redis_ptr=(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "HMSET FUF:%lu cname '%s' bname '%s' when %lu lng %f lat %f",
 											f_ptr->fence_id,
											f_ptr->fence_location.canonical_name,
											f_ptr->fence_location.display_banner_name,
											f_ptr->when,
 											f_ptr->fence_location.fence_location.longitude,
											f_ptr->fence_location.fence_location.latitude);

 		freeReplyObject(redis_ptr);
#endif

#ifdef __UF_TESTING
 		syslog(LOG_INFO, "%s: ADDED NEW UserFence: (bid:'%lu' fcname:'%s') and LINKED to USER's LIST (name:'%s' fence_count:'%lu') ", __func__,
 				 f_ptr->fence_id, f_ptr->fence_location.canonical_name,
				 ss_ptr->user.user_details.user_name, ss_ptr->session_user_fence_list.nEntries);
#endif

 		return f_ptr;
 	  }

 	  return NULL;

}


//--------------------- END OF ADD ROUTINES ----------------------------------


// ------------------- REMOVE ROUTINES -------------------------------------

//
//export function
//destructive
//all fences
//can be used when a user quit or I/O exception
//>>>>> LOCKS f_ptr <<<<<<
//
unsigned
RemoveUserFromAllFences (SessionService *ss_ptr)

{
	//we approach it from the User's fence list (which is hybrid User and Base) instead of Searching the
	//Master Registeries for the User: both should
	//yield the same effect due to stringent referencial data integrity checks throughout
	CHECK_SESSION_SERVICE_FOR_NULL(RemoveUserFromAllFences, -1);

	Fence *f_ptr=NULL;
	ListEntry *eptr=NULL;
	Session *sesn_ptr=container_of(ss_ptr, Session, sservice);
	int error=0;

	syslog(LOG_INFO, "RemoveUserFromAllFences: (uname='%s' uid='%lu') is member of (count='%u') Fences...",
			ss_ptr->user.user_details.user_name, ss_ptr->user.user_details.user_id, ss_ptr->session_user_fence_list.nEntries);

	//NEVER USE FOR LOOP CONSTRUCT FOR ITERATION
	while (ss_ptr->session_user_fence_list.nEntries!=0)
	{
		eptr=ss_ptr->session_user_fence_list.head;//pop them off from the head
		if (eptr)
		{
			f_ptr=(Fence *)eptr->whatever;

			FENCE_EVENTS_RWLOCK(RemoveUserFromAllFences);//do it for each fence in each iteration

			if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE))
			{
				syslog (LOG_INFO, "RemoveUserFromAllFences: REMOVING (cid='%lu' uname='%s' fence_count='%lu') from BaseFence (bid='%lu fcname='%s' user_count='%lu')...",
									 sesn_ptr->session_id,
									 ss_ptr->user.user_details.user_name, ss_ptr->session_user_fence_list.nEntries,
									 f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_user_sessions_list.nEntries);

				_f_RemoveUserFromBaseFence(ss_ptr, f_ptr);
			}
			else
			if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_USERFENCE))
			{
				syslog (LOG_INFO, "RemoveUserFromAllFences: REMOVING (cid='%lu' uname='%s' fence_count='%lu') from UserFence (bid='%lu fcname='%s' user_count='%lu')...",
													 sesn_ptr->session_id,
													 ss_ptr->user.user_details.user_name, ss_ptr->session_user_fence_list.nEntries,
													 f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_user_sessions_list.nEntries);

				_f_RemoveUserFromUserFence(ss_ptr, f_ptr);
			}
			else
			{
				//this is a truly sad condition... something is screwed up
				syslog (LOG_INFO, "RemoveUserFromAllFences: ERROR: COULD NOT DETERMINE FENCE TYPE  (bid='%lu fcname='%s' user_count='%lu') FOR (cid='%lu' uname='%lu' fence_count='%lu')...",
						f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_user_sessions_list.nEntries,
						sesn_ptr->session_id,
						ss_ptr->user.user_details.user_name, ss_ptr->session_user_fence_list.nEntries);
				error++;
			}

			FENCE_EVENTS_RWUNLOCK(RemoveUserFromAllFences);
		}
	}//while

	if (error)
	{

		syslog (LOG_INFO, "RemoveUserFromAllFences: ERROR (error_count='%d'): SOME FENCES HAD UNKNOWN TYPE...  (cid='%lu' uname='%s' fence_count='%lu')...",
				sesn_ptr->session_id,
				ss_ptr->user.user_details.user_name, ss_ptr->session_user_fence_list.nEntries);

		return 0;
	}

	return 1;//all good

}


//
//Export function
//given a fence id, remove the user from that fence
//body similar to 'RemoveUserFromAllFences()'
//>>>>> LOCKS f_ptr <<<<<<
//
unsigned
RemoveUserFromFence (Session *sesn_ptr, unsigned long fence_id)

{
	//we approach it from the User's fence list (which is hybrid User and Base) instead of Searching the
	//Master Registries for the User: both should
	//yield the same effect due to stringent data integrity checks throughout
	CHECK_SESSION_FOR_NULL(RemoveUserFromFence, -1);

	Fence *f_ptr=NULL;
	ListEntry *eptr=NULL;
	SessionService *ss_ptr=&(sesn_ptr->sservice);

	if ((f_ptr=_f_FindFenceInUserListByID(&(ss_ptr->session_user_fence_list), fence_id)))
	{
		FENCE_EVENTS_RWLOCK(RemoveUserFromFence);

		syslog(LOG_INFO, "RemoveUserFromFence: '%s' is member of '%u' Fences(Base or User)...", ss_ptr->user.user_details.user_name, ss_ptr->session_user_fence_list.nEntries);

		if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE))
		{
			syslog (LOG_INFO, "RemoveUserFromFence: REMOVING (cid='%lu' uname='%s' fence_count='%lu') from BaseFence (bid='%lu fcname='%s' user_count='%lu')...",
					 sesn_ptr->session_id,
					 ss_ptr->user.user_details.user_name, ss_ptr->session_user_fence_list.nEntries,
					 f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_user_sessions_list.nEntries);

			_f_RemoveUserFromBaseFence(ss_ptr, f_ptr);

			FENCE_EVENTS_RWUNLOCK(RemoveUserFromFence);

			return 1;
		}
		else
		if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_USERFENCE))
		{
			syslog (LOG_INFO, "RemoveUserFromFence: REMOVING (cid='%lu' uname='%s' fence_count='%lu') from UserFence (bid='%lu fcname='%s' user_count='%lu')...",
					 sesn_ptr->session_id,
					 ss_ptr->user.user_details.user_name, ss_ptr->session_user_fence_list.nEntries,
					 f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_user_sessions_list.nEntries);

			_f_RemoveUserFromUserFence(ss_ptr, f_ptr);

			FENCE_EVENTS_RWUNLOCK(RemoveUserFromFence);

			return 1;
		}
		else
		{
			//this is a truly sad condition... something is screwed up
			syslog (LOG_INFO, "RemoveUserFromFence: ERROR: COULD NOT DETERMINE FENCE TYPE  (bid='%lu fcname='%s' user_count='%lu') FOR (cid='%lu' uname='%s' fence_count='%lu')...",
					f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_user_sessions_list.nEntries,
					sesn_ptr->session_id,
					ss_ptr->user.user_details.user_name, ss_ptr->session_user_fence_list.nEntries);
		}
	}
	else
	{
		syslog (LOG_INFO, "RemoveUserFromFence (cid='%lu'): ERROR: COULD NOT REMOVE UserFence (bid='%lu') for (uname='%s' fence_count='%lu'): NOT IN HASH (hash_count='%lu')...",
				sesn_ptr->session_id,
				fence_id,
				sesn_ptr->sservice.user.user_details.user_name, sesn_ptr->sservice.session_user_fence_list.nEntries);//,
				//FenceRegistryIdHashTable.fNumEntries);
	}

	FENCE_EVENTS_RWUNLOCK(RemoveUserFromFence);

	return 0;

}


#define USER_FENCE_LIST			(0x1<<1) //requires key but otherwise visible
#define FENCE_USER_LIST			(0x1<<2)


//
//this a high level removal routine that employs  lower level helper service routines  defined below
//Remove user from ONE UserFence and unlinks as necessary
//Fence will be destroyed if fence stickiness rule is not satisfied. Destruction happens in another helper routine
//SessionService and User are not touched
//a mirror call is required for BaseFences.
//can be used in a loop to iterate over all user fences. perhaps not efficient, but safe and predictable
//
static Fence *
_f_RemoveUserFromUserFence (SessionService *ss_ptr, Fence *f_ptr)//unsigned long fence_id)
{
	CHECK_SESSION_SERVICE_FOR_NULL(RemoveUserFromUserFence, NULL);
	CHECK_FENCE_FOR_NULL(_f_RemoveUserFromUserFence);

	//Fence *f_ptr=NULL;
	//if (f_ptr=_f_FindFenceByID (master_fence_registry_ptr, fence_id))
	{
		unsigned score=0;

		//integrity check: is this user member of the fence
		if ((score=_f_CrossCheckUserInFenceAndFenceInUser(f_ptr, ss_ptr)))
		{
			if ((score&USER_FENCE_LIST)&&(score&FENCE_USER_LIST))
			{//both bits are set
#ifdef __UF_FULLDEBUG
				syslog(LOG_DEBUG, "%s: SUCCESSFULLY cross checked User<->Fence", __func__);
#endif

#if 0
				//is the user owns the user fence
				if (f_ptr->fence_owner_id==ss_ptr->user.user_details.id)
				{
					//TODO: OK we are not processing this condition at this stage
					syslog(LOG_DEBUG, "%s: Fence owner is leaving", __func__);
				}
#endif
				if (f_ptr->fence_user_sessions_list.nEntries==1)
				{//OK last user in Fence we'll destruct the fence unless sticky
					//if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_STICKY))//AA 0810
					{//sticky bit is on we'll leave the fence up, but stil unlink user
#ifdef __UF_FULLDEBUG
						syslog(LOG_DEBUG, "%s: STICKY BIT IS ON: Fence owner is leaving: user count will drop to zero.", __func__ );
#endif
						_f_RemoveUserFromUserFenceAndUnlinkUser(f_ptr, ss_ptr);
					}
					/*else //AA 0810 this cause crash in higher level routies that still expctsthe fence to be around
					{//destruction
						Session *sesn_ptr=container_of(ss_ptr, Session, sservice);//ss_ptr->session;
						_f_DestructUserFence(sesn_ptr, f_ptr);
					}*/
				}
				else
				{//more users remaining in the fence we just unlink user
					_f_RemoveUserFromUserFenceAndUnlinkUser(f_ptr, ss_ptr);
				}

				return f_ptr;
			}
			else
			{//one of the bits is unset
				syslog(LOG_DEBUG, "%s: one bit is unset", __func__);

				return NULL;
			}
		}//find user
		else
		{//user was not found
			syslog(LOG_DEBUG, "%s: COULD NOT find user", __func__);

			return NULL;
		}
	}
	/*else//some error
	{
		syslog(LOG_INFO, "RemoveUserFromUserFence: could not find fence in Master UserFence Registry" );
		return NULL;
	}*/

}


//
//this a high level removal routine that employs  lower level helper service routines  defined below
//Remove user from ONE BaseFence and unlinks as necessary
//BaseFence will be NOT destroyed
//SessionService and User are not touched
//a mirror call is defined for UserFences, albeit slightly different rules.
//can be used in a loop to iterate over all user fences. perhaps not efficient, but safe and predictable
//
inline static Fence *
_f_RemoveUserFromBaseFence (SessionService *ss_ptr, Fence *f_ptr)//unsigned long fence_id)
{
	CHECK_SESSION_SERVICE_FOR_NULL(RemoveUserFromBaseFence, NULL);
	CHECK_FENCE_FOR_NULL(_f_RemoveUserFromBaseFence);

	//Fence *f_ptr=NULL;
	//if (f_ptr=_f_FindFenceByID (master_base_fence_registry_ptr, fence_id))
	{
		unsigned score=0;

		//integrity check: is this user member of the fence
		if ((score=_f_CrossCheckUserInFenceAndFenceInUser(f_ptr, ss_ptr)))
		{
			if (score&USER_FENCE_LIST&&score&FENCE_USER_LIST)
			{//both bits are set
				syslog(LOG_INFO, "_f_RemoveUserFromBaseFence: SUCCESSFULLY cross checked User<->Fence" );
#if 0
				//is the user owns the user fence
				if (f_ptr->fence_owner_id==ss_ptr->user.user_details.id)
				{
					//TODO: OK we are not processing this condition at this stage
					syslog(LOG_INFO, "_f_RemoveUserFromUserFence: Fence owner is leaving" );
				}
#endif
				if (f_ptr->fence_user_sessions_list.nEntries==1)
				{//OK last user in Fence is leaving, but unlike UserFence we never destruct upon this condition

						syslog(LOG_INFO, "_f_RemoveUserFromBaseFence: BaseFence count will drop to zero." );
						_f_RemoveUserFromBaseFenceAndUnlinkUser(f_ptr, ss_ptr);

				}
				else
				{//more users remaining in the fence we just unlink user
					_f_RemoveUserFromBaseFenceAndUnlinkUser(f_ptr, ss_ptr);
				}

				return f_ptr;
			}
			else
			{//one of the bits is unset
				syslog(LOG_INFO, "_f_RemoveUserFromBaseFence: one bit is unset" );
				return NULL;
			}
		}//find user
		else
		{//user was not found
			syslog(LOG_INFO, "_f_RemoveUserFromBaseFence: COULD NOT find user" );
			return NULL;
		}
	}
	/*else//some error
	{
		syslog(LOG_INFO, "RemoveUserFromBaseFence: could not find fence in Master BaseFence Registry" );
		return NULL;
	}*/

}


//
//essentially we should be able to cross reference the user across the fence and fence across the user
//ONE USER_FENCE at a time
//can be used in a loop to iterate over all FENCE-USER twins
//works for both USerFence and BAseFence
//important data integrity check
//bits are set to indicate status of linking
//
inline static unsigned
_f_CrossCheckUserInFenceAndFenceInUser(Fence *f_ptr, SessionService *ss_ptr)
{
   ListEntry *eptr=NULL;
   SessionService *ss_ptr2=NULL;
   Fence *f_ptr2=NULL;
   unsigned score=0x1;

   //first check user in Fence's List
   for (eptr=f_ptr->fence_user_sessions_list.head; eptr; eptr=eptr->next)
   {
	   ss_ptr2=(SessionService *)eptr->whatever;
	   if (ss_ptr2==ss_ptr)
	   {
		   score|=FENCE_USER_LIST;
		   break;
	   }
   }

   //second check fence in Users's List
   for (eptr=ss_ptr->session_user_fence_list.head; eptr; eptr=eptr->next)
   {
	   f_ptr2=(Fence *)eptr->whatever;
	   if (f_ptr2==f_ptr)
	   {
		   score|=USER_FENCE_LIST;
		   break;
	   }
   }

   return score;

}


/*
*
* '{ "_cmdidx": "7", "count": "Australia", "admina": "New South Wales",  "locl": "Auburn",  "bid": 382466952, "name": "Auburn", "_sreqid": 2, "_reqid": 1,
* "cid": 733477108, "type": "fence_config", "members": [ { "nick": "ufusr", "mode": "+o" }, { "nick": "aarcha", "mode": "+o" } ] }'
*
*/

#define USER_LOCALITY \
   ss_ptr->user.user_details.user_location_initialised?ss_ptr->user.user_details.user_location.locality:\
		   (ss_ptr->user.user_details.user_location_by_server_initialised?ss_ptr->user.user_details.user_location_by_server.locality:l)
#define USER_LONGITUDE \
		ss_ptr->user.user_details.user_location_initialised?ss_ptr->user.user_details.user_location.longitude:\
		  				 (ss_ptr->user.user_details.user_location_by_server_initialised?ss_ptr->user.user_details.user_location_by_server.longitude:0.0)
#define USER_LATITUDE \
   		ss_ptr->user.user_details.user_location_initialised?ss_ptr->user.user_details.user_location.latitude:\
   		  				 (ss_ptr->user.user_details.user_location_by_server_initialised?ss_ptr->user.user_details.user_location_by_server.latitude:0.0)


//
//>>>>RDLOCKS
//
json_object *
MakeSessionFenceListInJason (Session *sesn_ptr)
{
   json_object *jobj;//=json_object_new_object();
   Fence *f_ptr;

	   /*Creating a json array*/
	   json_object *jarray = json_object_new_array();

	   syslog(LOG_INFO, "MakeSessionFencesInJason (cid='%lu'): Making Fences list for Session...", sesn_ptr->session_id);

	   ListEntry *eptr = NULL;
	   if (sesn_ptr->sservice.session_user_fence_list.nEntries == 0) {
		   syslog(LOG_INFO, "MakeSessionFencesInJason (cid='%lu'): COULD NOT MAKE FENCE LIST FOR SESSION: No Fences found in Session", sesn_ptr->session_id);
		   return NULL;
	   }

	  //UserFence registry
		for (eptr=sesn_ptr->sservice.session_user_fence_list.head; eptr; eptr=eptr->next) {
			jobj = json_object_new_object();
			f_ptr = FENCE(eptr);

			FENCE_EVENTS_RDLOCK(MakeSessionFenceListInJason);

			json_object_object_add (jobj,"fname", json_object_new_string(FENCE(eptr)->fence_location.display_banner_name));
			json_object_object_add (jobj,"bid", json_object_new_int(FENCE(eptr)->fence_id));
			json_object_object_add (jobj,"fcname", json_object_new_string(FENCE(eptr)->fence_location.canonical_name));

			FENCE_EVENTS_RWUNLOCK(MakeSessionFenceListInJason);

			json_object_array_add(jarray, jobj);
		}

	   return jarray;

}


//
// >>> RDLOCK
//


json_object *
MakeFenceMembersInJson (Fence *f_ptr)
{
	ListEntry *eptr=NULL;
	SessionService *ss_ptr=NULL;

	json_object *jobj;//=json_object_new_object();

	/*Creating a json array*/
	json_object *jarray=json_object_new_array();


	syslog(LOG_INFO, "MakeFenceMembersInJson: preparing json representation for '%s'. User count '%u'", f_ptr->fence_location.display_banner_name, f_ptr->fence_user_sessions_list.nEntries);

	//first check user in Fence's List

	FENCE_EVENTS_RDLOCK(MakeFenceMembersInJson);

	for (eptr=f_ptr->fence_user_sessions_list.head; eptr; eptr=eptr->next)
	{
	   static const char *l="unknown";
	   jobj=json_object_new_object();

	   ss_ptr=(SessionService *)eptr->whatever;

	   json_object_object_add (jobj,"nick", json_object_new_string(ss_ptr->user.user_details.user_name));
	   json_object_object_add (jobj,"uid", json_object_new_int(ss_ptr->user.user_details.user_id));
	   json_object_object_add (jobj,"locality", json_object_new_string(USER_LOCALITY));
	   json_object_object_add (jobj,ACCOUNT_JSONATTR_LATITUDE, json_object_new_double(USER_LATITUDE));
	   json_object_object_add (jobj,ACCOUNT_JSONATTR_LONGITUDE,  json_object_new_double(USER_LONGITUDE));


	   if (f_ptr->fence_owner_id==ss_ptr->user.user_details.user_id)
		   json_object_object_add (jobj,"mode", json_object_new_string("+r"));
	   else
		   json_object_object_add (jobj,"mode", json_object_new_string("+r"));

	   json_object_array_add(jarray, jobj);
	   //json_object_put(jobj); //this happens in the calling environment

	}

	FENCE_EVENTS_RWUNLOCK(MakeFenceMembersInJson);

	syslog(LOG_INFO, "MakeFenceMembersInJson: finished json representation for '%s'. User count '%u'", f_ptr->fence_location.display_banner_name, f_ptr->fence_user_sessions_list.nEntries);

	return jarray;


}


json_object *
GetFencesNearbyInJson (const Session *sesn_ptr, const char *baseloc, unsigned fence_type)
   {
#if 0
	   json_object *jobj;//=json_object_new_object();
	   redisReply *redis_ptr;

	   /*Creating a json array*/
	   json_object *jarray=json_object_new_array();

	   syslog(LOG_INFO, "GetFencesNearbyInJson: preparing json representation for baseloc '%s' ZRANGEBYLEX BF '[%s' '(%s\\xff'", baseloc, baseloc, baseloc);
	   //redis_ptr=(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "ZRANGEBYLEX BF '[%s' '(%s\\xff'", baseloc, baseloc);
	   redis_ptr=(*sesn_ptr->persistance_backend->send_command)(sesn_ptr, "zrange 'BF' 0 -1");

	   if (redis_ptr->type==REDIS_REPLY_ERROR)
	   {
		   syslog(LOG_INFO, "GetFencesNearbyInJson: ERROR: REDIS RESULTSET for baseloc '%s'. Error: '%s'", baseloc, redis_ptr->str);
		   return NULL;
	   }
	   if (redis_ptr->type != REDIS_REPLY_ARRAY)
	   {
		   syslog(LOG_INFO, "GetFencesNearbyInJson: ERROR: UNEXPECTED RESULT TYPE for baseloc '%s'. Type: '%d'", baseloc, redis_ptr->type);
		   return NULL;
	   }

	   syslog(LOG_INFO, "GetFencesNearbyInJson: RESULT: Received (%d) elements '%s'", redis_ptr->elements, redis_ptr->str);
	   int i;
	   for (i=0; i < redis_ptr->elements; ++i)
	   {
		   syslog(LOG_INFO, "GetFencesNearbyInJson: RESULT (%d): '%s'", i, baseloc, redis_ptr->element[i]->str);
	   }


		freeReplyObject(redis_ptr);
#endif
#if 0
	   json_object *jobj;//=json_object_new_object();

	   /*Creating a json array*/
	   json_object *jarray=json_object_new_array();


	   syslog(LOG_INFO, "GetFencesNearbyInJson: preparing json representation for baseloc '%s' ", baseloc);
	   List *lst_ptr=master_base_fence_registry_ptr;
	   ListEntry *eptr=NULL;
	   //if (lst_ptr->nEntries==0 || !fence_canonical_name)  return (Fence *)NULL;

	  //UserFence registry
		for (eptr=lst_ptr->head; eptr; eptr=eptr->next)
		{
			if (strncasecmp(FENCE(eptr)->fence_location.canonical_name, baseloc, strlen(baseloc))==0)
			 {
				jobj=json_object_new_object();
				json_object_object_add (jobj,"fname", json_object_new_string(FENCE(eptr)->fence_location.display_banner_name));
				json_object_object_add (jobj,"longitude", json_object_new_double(FENCE(eptr)->fence_location.fence_location.longitude));
				json_object_object_add (jobj,"latitude", json_object_new_double(FENCE(eptr)->fence_location.fence_location.latitude));
				json_object_object_add (jobj,"nusers", json_object_new_int(FENCE(eptr)->fence_user_sessions_list.nEntries));
				json_object_object_add (jobj,"bid", json_object_new_int(FENCE(eptr)->fence_id));
				json_object_object_add (jobj,"ftype", json_object_new_string("UFFENCE"));
				//json_object_object_add (jobj,"ftype", json_object_new_int(FENCE(eptr)->fence_user_sessions_list.nEntries));
				json_object_array_add(jarray, jobj);

				syslog(LOG_INFO, "_f_FindFenceContainingBaseloc: Found BaseFence '%s' containing baseloc: '%s'. User count: %i",
						baseloc, baseloc, FENCE(eptr)->fence_user_sessions_list.nEntries);

			 }
		}

		lst_ptr=master_fence_registry_ptr;
		for (eptr=lst_ptr->head; eptr; eptr=eptr->next)
		{
			if (strncasecmp(FENCE(eptr)->fence_location.canonical_name, baseloc, strlen(baseloc))==0)
			 {
				jobj=json_object_new_object();
				json_object_object_add (jobj,"fname", json_object_new_string(FENCE(eptr)->fence_location.display_banner_name));
				json_object_object_add (jobj,"longitude", json_object_new_double(FENCE(eptr)->fence_location.fence_location.longitude));
				json_object_object_add (jobj,"latitude", json_object_new_double(FENCE(eptr)->fence_location.fence_location.latitude));
				json_object_object_add (jobj,"nusers", json_object_new_int(FENCE(eptr)->fence_user_sessions_list.nEntries));
				json_object_object_add (jobj,"bid", json_object_new_int(FENCE(eptr)->fence_id));
				json_object_object_add (jobj,"ftype", json_object_new_string("USEREFENCE"));
				//json_object_object_add (jobj,"ftype", json_object_new_int(FENCE(eptr)->fence_user_sessions_list.nEntries));
				json_object_array_add(jarray, jobj);

				syslog(LOG_INFO, "_f_FindFenceContainingBaseloc: Found UserFence '%s' containing baseloc: '%s'. User count: %i",
						baseloc, baseloc, FENCE(eptr)->fence_user_sessions_list.nEntries);

			 }
		}


	   return jarray;
#endif
	   return NULL;

   }

//(gdb) b bp
   //prevent from being optimised out
//__attribute__((noinline)) void __bp(void) { asm (""); }
#define EMBED_BREAKPOINT bp()
void bp(void) {}

//
//destructive: all resources associated with _a Fence_ are removed and completely unlinked.
//DO NOT CALL ON A LOOP WITH  ListEntry->next s you'd be shooting yourself in the foot as you cycle through loop iteration
//because the structure of the list will have changed
//assumes USers are in Fence and will loop unlink destruct each
//user service routines to unlink
//
static int
_f_DestructUserFence (Session *sesn_ptr, Fence *f_ptr)

{
	CHECK_FENCE_FOR_NULL(_f_DestructUserFence);

	//1)unlink from users
	{//block 1
		SessionService *ss_ptr=NULL;
		ListEntry *eptr=NULL;

#ifdef __UF_FULLDEBUG
		syslog(LOG_INFO, "%s: (bid='%lu' fcname='%s') has (user_count='%lu') Sessions...", __func__,
					f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_user_sessions_list.nEntries);
#endif

		//RemoveFromHash(&FenceRegistryIdHashTable, (void *) &f_ptr->fence_id);
		//RemoveFromHash(&FenceRegistryCanonicalNameHashTable, (void *) f_ptr->fence_location.canonical_name);

		//first get the queue out of the way
		_f_DestructFenceMessageQueue (f_ptr);

		//for each session in the Fence unlink it
		while (f_ptr->fence_user_sessions_list.nEntries != 0) {//normally do it when one user is left
			if ((eptr=f_ptr->fence_user_sessions_list.head)) {
			 ss_ptr=(SessionService *)eptr->whatever;
			 //1) non destructive unlinking
			 _f_RemoveUserFromUserFenceAndUnlinkUser(f_ptr, ss_ptr);
			}
		}//while


		//2) destructive: a contained object
		 //TODO: look for more contained objects

#if 0
		redisReply *redis_ptr=(*sesn_ptr->persistance_backend->send_command)
				(sesn_ptr, "ZREM BF 0 %s", f_ptr->fence_location.canonical_name);
		freeReplyObject(redis_ptr);

		PERSIST_REMOVE_USERFENCE;

		//RemoveFromHash(&FenceRegistryIdHashTable, (void *) &f_ptr->fence_id);
		//RemoveFromHash(&FenceRegistryCanonicalNameHashTable, (void *) f_ptr->fence_location.canonical_name);
#endif

		DestructLocationDescription (&f_ptr->fence_location.fence_location);

		 //3)destructive: ListEntry holding Fence object removed from Master List
		//RemoveThisFromList(master_fence_registry_ptr, f_ptr);
		 //4)destructive: free actual fence object
		pthread_rwlockattr_destroy (&(f_ptr->fence_events.rwattr));
		memset(f_ptr, 0, sizeof(Fence));
		free(f_ptr);

		return 1;
	}//block 1

	return 0;

}


//
//non destructive: service routine called in the context of larger remove transaction
//Original Fence entity lives no, no freeing of resources
//f_ptr represents a Base Fence, which is unaffected in Master BaseFence Registry
//User's SessionService is removed from the BaseFence List
//and BaseFence is removed form the User's List of Fences
//dont call this directly unless you understand the plumbing of data structure
//
inline static Fence *
_f_RemoveUserFromBaseFenceAndUnlinkUser(Fence *f_ptr, SessionService *ss_ptr)
{
	if (unlikely(f_ptr==NULL || ss_ptr==NULL))	return;

	//2)unlink and free this Fence reference from User's List of Fences
	  RemoveThisFromList (&ss_ptr->session_user_fence_list, f_ptr);//session locked at higher level


	 //3)unlink and free this ServiceSession (User) reference from  Fence's List
	  RemoveThisFromList (&f_ptr->fence_user_sessions_list, ss_ptr);

	//now UNreference this  _local_ BaseFence in the User datatype
	  ///ss_ptr->user.user_details.base_fence_local=NULL;

#ifdef __UF_TESTING
	  syslog(LOG_DEBUG, "%s: SUCCESS: REMOVED (uid='%lu' fence_count='%lu') from (bid='%lu' user_count='%lu')", __func__,
				ss_ptr->user.user_details.user_id, ss_ptr->session_user_fence_list.nEntries,
				f_ptr->fence_id, f_ptr->fence_user_sessions_list.nEntries);
#endif

	 return f_ptr;

}


//
//non destructive: service routine called in the context of larger remove transaction
//Original Fence entity lives no, no freeing of resources
//Fence exists in Fence Hash table
//remove a User's SessionService from the Fence's List of Users
//
inline static Fence *
_f_RemoveUserFromUserFenceAndUnlinkUser(Fence *f_ptr, SessionService *ss_ptr)
{
	if (unlikely(f_ptr==NULL || ss_ptr==NULL))	return;

	RemoveThisFromList (&(ss_ptr->session_user_fence_list), f_ptr);

	//do locking at higher level
	RemoveThisFromList (&(f_ptr->fence_user_sessions_list), ss_ptr);

#ifdef __UF_TESTING
	syslog(LOG_INFO, "%s: SUCCESS: REMOVED (uid='%lu' fence_count='%lu') from (bid='%lu' user_count='%lu')", __func__,
		ss_ptr->user.user_details.user_id, ss_ptr->session_user_fence_list.nEntries,
		f_ptr->fence_id, f_ptr->fence_user_sessions_list.nEntries);
#endif

	return f_ptr;

}

// ---------- --------------- END OF REMOVE ROUTINES ---------------------


// -------------------------- FIND ROUTINES ------------------------------

//
//Given a user find their associated local BaseFence. Current rules : user allowed one "Local" Base fence,
//but can have many "remote" Base fences
//attr: F_ATTR_BASEFENCE_LOCAL || F_ATTR_BASEFENCE_REMOTE
//TODO: this flawed. We cannot set bit F_ATTR_BASEFENCE_REMOTE for a object that is shared aongs users (one to many)
//we can still check for F_ATTR_BASEFENCE
//not sure how useful this function anymore
//as the user's list of fences is a hybrid list, the ony way to reliably check if a BASE fence is local or remote
//is to store a local copy of the BaseFence pointer and compare against it. Any other base fence in the list that does not
//equate with the local copy of the base fence is a remote one
//
Fence *
FindBaseFenceForUser (SessionService *ss_ptr, unsigned attr)

{
	CHECK_SESSION_SERVICE_FOR_NULL(FindBaseFence, NULL);

	Fence *f_ptr;
	ListEntry *eptr=NULL;

	//TODO: needs READLOCK
	for (eptr=ss_ptr->session_user_fence_list.head; eptr; eptr=eptr->next)
	{
		f_ptr=(Fence *)eptr->whatever;
		if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE))//&&F_ATTR_IS_SET(f_ptr->attrs, attr))
		{
		 syslog(LOG_INFO, "FindBaseFenceForUser: Found Local BaseFence '%s' for User: '%s'.",
				 f_ptr->fence_location.canonical_name, ss_ptr->user.user_details.user_name);
		 return f_ptr;
		}
	}

	syslog(LOG_INFO, "FindBaseFenceForUser: COULD NOT find Local BaseFence for User: '%s'.",
					 ss_ptr->user.user_details.user_name);
	return NULL;

}


//
//Searches Hash. Canonical names only apply to network created base fences
//
Fence *
FindUserFenceByCanonicalName (const char *fence_canonical_name)

{
	CHECK_CANONICAL_NAME_FOR_NULL_POINTER(FindUserFenceByCanonicalName);

	{

		Fence *f_ptr=NULL;
/*
		f_ptr=(Fence *)HashLookup(&FenceRegistryCanonicalNameHashTable, (void *)fence_canonical_name);
		if (f_ptr)
		{
			syslog(LOG_INFO, "FindUserFenceByCanonicalName: FOUND FENCE '%s'...", f_ptr->fence_location.canonical_name);
			if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_USERFENCE)) return f_ptr;
			else
			{
				syslog(LOG_INFO, "FindUserFenceByCanonicalName: FENCE '%s' IS NOT OF USER TYPE", f_ptr->fence_location.canonical_name);
				return NULL;
			}

		}
		else
*/
		{
			syslog(LOG_INFO, "FindUserFenceByCanonicalName: COULD NOT FIND FENCE '%s' HASH TABLE", fence_canonical_name);

			return NULL;
		}

	}

	return NULL;

}


//
//Searches Hash. Canonical names only apply to network created base fences
//
Fence *
FindBaseFenceByCanonicalName (const char *fence_canonical_name)

{
  CHECK_CANONICAL_NAME_FOR_NULL_POINTER(FindBaseFenceByCanonicalName);

	{
	  Fence *f_ptr=NULL;

	  //f_ptr=(Fence *)HashLookup(&FenceRegistryCanonicalNameHashTable, (void *)fence_canonical_name);
	  if ((f_ptr) && (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE)))return f_ptr;
	  else return NULL;
	}

}


//
//service routine given a fence_id searches Hash
//
Fence *
FindFenceById (const unsigned long fence_id)
{
	Fence *f_ptr=NULL;

	//return (Fence *)HashLookup(&FenceRegistryIdHashTable, (void *)&fence_id);

}




Fence *
IsUserMemberOfFenceByCanonicalName (const List *const lst_ptr, const char *fence_canonical_name)

{
	return (_f_FindFenceInUserListByCanonicalName(lst_ptr, fence_canonical_name));

}


//
//search Session's List of fences and a matching fence_id
//looks up immutable field fence_id o no need for locking
//
Fence *
IsUserMemberOfFence (const List *const lst_ptr, const unsigned long fence_id)

{
	return (_f_FindFenceInUserListByID(lst_ptr, fence_id));

}

Fence *AmIMemberOfFence (const List *const lst_ptr, const unsigned long fence_id);
Fence *AmIMemberOfFence (const List *const lst_ptr, const unsigned long fence_id)

{
	return (_f_FindFenceInUserListByID(lst_ptr, fence_id));

}


//List is Fence's list of user Sessions
User *IsUserMemberOfFenceByUserId (List *lst_ptr, unsigned long uid);
User *IsUserMemberOfFenceByUserId (List *lst_ptr, unsigned long uid)
{		ListEntry *eptr;

		CHECK_LIST_POINTER_FOR_NULL(_f_FindFenceInUserByID);

		if (lst_ptr->nEntries==0 || uid<=0)
		{
			fprintf(stderr, "IsUserMemberOfFenceByUserId (pid:'%lu'): ERROR IN PARAMS: nEntries in List: '%lu'. UID: '%lu'\n",
					pthread_self(), lst_ptr->nEntries, uid);

			return (User *)NULL;
		}

		//TODO: this needs to be protected by read lock
		User *u_ptr=NULL;
		{

			for (eptr=lst_ptr->head; eptr && eptr->whatever; eptr=eptr->next)
			{
				//u_ptr=&(((Session *)eptr->whatever)->sservice.user);
			   if (((User *)(eptr->whatever))->user_details.user_id==uid)
				if (u_ptr->user_details.user_id==uid)
				{
				   return ((User *)(eptr->whatever));
				}
			}
		}

		return NULL;

}

//
//searches in any List, but it designed to be used in searching Session's list of fences.
//looks up immutable field fence_id so there is no need to lock f_ptr
//user list is on average of small size
//No Fence locking is required, List needs lock at higher level
//
inline static Fence *
_f_FindFenceInUserListByID (const List *const lst_ptr, const unsigned long fence_id)

{
	ListEntry *eptr;

	CHECK_LIST_POINTER_FOR_NULL(_f_FindFenceInUserByID);

	if (lst_ptr->nEntries==0 || fence_id<=0)
	{
		fprintf(stderr, "_f_FindFenceInUserListByID (pid:'%lu'): INVALID ence_id parameter was passed or List entries = 0 \n", pthread_self());

		return (Fence *)NULL;
	}

	//TODO: this needs to be protected by read lock
	Fence *f_ptr=NULL;
	{
		Fence *f_ptr_hash=NULL;
		//f_ptr_hash=FindFenceById(fence_id);

		for (eptr=lst_ptr->head; eptr; eptr=eptr->next)
		{
		   if (FENCE_ID(eptr)==fence_id)
			{
			   //cross check with hash
			   if (1)//f_ptr_hash && f_ptr_hash==FENCE(eptr))
			   {
				   f_ptr=FENCE(eptr);
				   fprintf(stderr, "_f_FindFenceInUserListByID (pid:'%lu'): SUCCESS: Fence (bid='%lu') in USER's FenceList \n", pthread_self(), f_ptr->fence_id);
				   break;
			   }
			   else
			   {
				   fprintf(stderr, "_f_FindFenceInUserListByID (pid:'%lu'): SEVERE ERROR: FOUND USER IN OWN LIST BUT NOT IN HASH)", pthread_self());
				   break;
			   }
			}
		}
	}

	return f_ptr;

}

//
//Session's fence List
//
inline static Fence *
_f_FindFenceInUserListByCanonicalName (const List *const lst_ptr, const char *fence_canonical_name)

{
	ListEntry *eptr;

	//CHECK_LIST_POINTER_FOR_NULL(_f_FindFenceInUserByID);

	if (lst_ptr->nEntries==0 || !fence_canonical_name)
	{
		syslog(LOG_ERR, "_f_FindFenceInUserListByCanonicalName  (pid:'%lu'): INVALID canonical name parameter was passed or List entries = 0 ", pthread_self());

		return (Fence *)NULL;
	}

	//TODO: this needs to be protected by read lock
	Fence *f_ptr_hash=NULL;
	{
		//f_ptr_hash=(Fence *)HashLookup(&FenceRegistryCanonicalNameHashTable, (void *)fence_canonical_name);;

		for (eptr=lst_ptr->head; eptr; eptr=eptr->next)
		{
		   if (strncasecmp(fence_canonical_name, FENCE(eptr)->fence_location.canonical_name, strlen(FENCE(eptr)->fence_location.canonical_name))==0)
			{
			   //cross check with hash
			   if (f_ptr_hash && (strncasecmp(fence_canonical_name, f_ptr_hash->fence_location.canonical_name, strlen(f_ptr_hash->fence_location.canonical_name))==0))
			   {
				   syslog(LOG_ERR, "_f_FindFenceInUserListByCanonicalName (pid:'%lu'): SUCCESS: FOUND USER in bid='%lu' fcname='%s'", pthread_self(), f_ptr_hash->fence_id, f_ptr_hash->fence_location.canonical_name);
				   return f_ptr_hash;
			   }
			   else break;
			}
		}
	}

	syslog(LOG_ERR, "_f_FindFenceInUserListByCanonicalName (pid:'%lu'): SEVERE ERROR: FOUND USER IN OWN LIST BUT NOT IN HASH)", pthread_self());

	return NULL;

}





void SummariseUserFenceConfiguration (void)
{
	//MASTER_USER_FENCE_RDLOCK(SummariseUserFenceConfiguration);
	//SummariseFenceConfiguration (master_fence_registry_ptr, "UserFence");
	//MASTER_USER_FENCE_RWUNLOCK(SummariseUserFenceConfiguration);
}


void
SummariseBaseFenceConfiguration (void)
{
	//MASTER_BASE_FENCE_RDLOCK(SummariseBaseFenceConfiguration);
	//SummariseFenceConfiguration (master_base_fence_registry_ptr, "BaseFence");
	//MASTER_BASE_FENCE_RWUNLOCK(SummariseBaseFenceConfiguration);
}

//cross referenced reporting of users and fencesto check on the referencial integrity of lists across the network
static void SummariseFenceConfiguration (List *lst_ptr, const char *label)

{
	ListEntry *eptr;
	Fence *f_ptr;


	if (lst_ptr->nEntries==0 )
	{
		syslog (LOG_INFO, "%s: List has empty Fences in it '%d'", label, lst_ptr->nEntries);
		return;
	}

	syslog (LOG_INFO, ":::- Summary of %s Configuration Network wide -:::", label);
	syslog (LOG_INFO, "%s: List has '%d' Fences in it:", label, lst_ptr->nEntries);

	for (eptr=lst_ptr->head; eptr; eptr=eptr->next)
	{
	 f_ptr=(Fence *)eptr->whatever;
	 syslog (LOG_INFO, "%s: Fence: '%s'. ID: '%lu'. Number of Users: '%u' ",
			 label, f_ptr->fence_location.canonical_name, f_ptr->fence_id, f_ptr->fence_user_sessions_list.nEntries );
	 {//block1: fence list of users
		 ListEntry *eptr2;
		 SessionService *ss_ptr;
		 for (eptr2=f_ptr->fence_user_sessions_list.head; eptr2; eptr2=eptr2->next)
		 {
			 ss_ptr=(SessionService *)eptr2->whatever;
			 syslog (LOG_INFO, "`-- User name: '%s'. User's Fence count: '%u'",
					 ss_ptr->user.user_details.user_name, ss_ptr->session_user_fence_list.nEntries);
			 {//block2 user list of fences
				 ListEntry *eptr3;
				 Fence *f_ptr2;
				 for (eptr3=ss_ptr->session_user_fence_list.head; eptr3; eptr3=eptr3->next)
				 {
					 f_ptr2=(Fence *)eptr3->whatever;
					 syslog (LOG_INFO, "`---- Fence: '%s'. Fence's User count: '%u' ",
							 f_ptr2->fence_location.canonical_name, f_ptr2->fence_user_sessions_list.nEntries);
				 }

			 }//block2

		 }
	 }//block 1

	}

}


   // -------------------------- END OF FIND ROUTINES ------------------



