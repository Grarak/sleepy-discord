#pragma once
#include <cpr/cpr.h>
#ifndef NONEXISTENT_CPR
#include "http.h"

namespace SleepyDiscord {
	class CPRSession : public GenericSession {
	public:
		inline void setUrl(const std::string& url) {
			session.SetUrl(cpr::Url{ url });
		}
		inline void setBody(const std::string* jsonParameters) {
			session.SetBody(cpr::Body{ *jsonParameters });
		}
		void setHeader(const std::vector<HeaderPair>& header);
		void setMultipart(const std::initializer_list<Part>& parts);
		void setResponseCallback(const ResponseCallback& callback) {
			responseCallback = callback;
		}
		Response request(RequestMethod method);
	private:
		Response perform(RequestMethod method);
		cpr::Session session;
		//muiltpart is needs to be here when uploading images,
		//so that it's not deallocated when making the request
		cpr::Multipart muiltpart = {};
		ResponseCallback responseCallback;
	};

	typedef CPRSession Session;
}

#endif