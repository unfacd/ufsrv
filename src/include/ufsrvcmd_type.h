#ifndef UFSRVCMD__TYPE__H__
#define UFSRVCMD__TYPE__H__

#include <session.h>
#include <ufsrvresult_type.h>
#include <WebSocketMessage.pb-c.h>
#include <json/json.h>


	struct UfsrvCommand {
                            UFSRVResult * (*callback) (Session *, WebSocketMessage *, struct json_object *);
		   };
	typedef struct UfsrvCommand UfsrvCommand;


#endif
