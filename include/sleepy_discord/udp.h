#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include <functional>

namespace SleepyDiscord {
	class GenericUDPClient {
	public:
		typedef std::function<void()> SendHandler;
		typedef std::function<void(const std::vector<uint8_t>&)> ReceiveHandler;

		virtual ~GenericUDPClient() = default;

		virtual bool connect(const std::string& to, const uint16_t port) = 0;
		virtual void send(
			const uint8_t* buffer,
			size_t bufferLength,
			SendHandler handler = [](){}
		) = 0;
		inline virtual void setReceiveHandler(ReceiveHandler handler) {
			receive_handler = std::move(handler);
		}
		inline virtual void unsetReceiveHandler() {
			receive_handler = ReceiveHandler();
		}
		virtual std::vector<uint8_t> waitForReceive() = 0;

		inline void send(const std::vector<uint8_t>& buffer, SendHandler handler = [](){}) {
			send(buffer.data(), buffer.size(), handler);
		}
	protected:
		ReceiveHandler receive_handler;
	};
}
