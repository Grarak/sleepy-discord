#pragma once
#include <string>
#include "json_inputstream.h"
#include "websocket_connection.h"
#include "timer.h"

namespace SleepyDiscord {
	class GenericMessageReceiver {
	public:
		virtual ~GenericMessageReceiver() = default;
		virtual void initialize() {}                                  //called when ready to recevie messages
		virtual void handleFailToConnect() {}                         //called when connection has failed to start
                virtual void processStream(JsonInputStream &is) = 0;
		virtual void processMessage(const std::string & message) = 0; //called when recevicing a message
		virtual void processCloseCode(const int16_t /*code*/) {}
		WebsocketConnection connection;                               //maybe this should be set to protected?
	protected:
		int consecutiveReconnectsCount = 0;
		Timer reconnectTimer;

		inline const time_t getRetryDelay() {
			return consecutiveReconnectsCount < 50 ? consecutiveReconnectsCount * 5000 : 5000 * 50;
		}
	};
}