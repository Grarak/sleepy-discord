#include "voice_connection.h"
#ifdef SLEEPY_VOICE_ENABLED
#include <sodium.h>
#include "client.h"

namespace SleepyDiscord {
	VoiceConnection::VoiceConnection(BaseDiscordClient* client, VoiceContext& _context) :
		origin(client), context(_context), sSRC(0), port(0), nextTime(0),
#if !defined(NONEXISTENT_OPUS)
		encoder(nullptr), decoder(nullptr),
#endif
		secretKey()
	{}

	void VoiceConnection::disconnect() {
		stopSpeaking();
		UDP.unsetReceiveHandler();
		std::string update;
		/*The number 103 comes from the number of letters in this string + 1:
		{"op":4,"d":{"guild_id":"18446744073709551615","channel_id":null,"self_mute":false,"self_deaf":false}}
		*/
		update.reserve(103);
		update +=
			"{"
				"\"op\":4,"
				"\"d\":{"
					"\"guild_id\":\""; update += context.serverID; update += "\","
					"\"channel_id\":null,"
					"\"self_mute\":false,"
					"\"self_deaf\":false"
				"}"
			"}";
		origin->send(update, origin->connection);

		if (state & State::CONNECTED)
			origin->disconnect(1000, "", connection);
		if (heart.isValid())
			heart.stop(); //Kill
		speechTimer.stop();
		listenTimer.stop();
		//deal with raw pointers
		//Sorry about this c code, we are dealing with c libraries
		if (encoder != nullptr) {
			opus_encoder_destroy(encoder);
			encoder = nullptr;
		}
		if (decoder) {
			decoder.reset();
		}
		state = static_cast<State>(state & ~State::CONNECTED);
	}

	void VoiceConnection::initialize() {
		if (state == NOT_CONNECTED)
			return;

		std::string resume;
		/*The number 77 comes from the number of letters in this string + 1:
		{"op":7,"d":{"server_id":"18446744073709551615","session_id":"","token":""}}
		*/
		resume.reserve(77 + context.sessionID.length() + context.token.length());
		resume +=
			"{"
				"\"op\":7," //RESUME
				"\"d\":{"
					"\"server_id\":\"" ; resume += context.serverID ; resume += "\","
					"\"session_id\":\""; resume += context.sessionID; resume += "\","
					"\"token\":\""     ; resume += context.token    ; resume += "\""
				"}"
			"}";
		origin->send(resume, origin->connection);
	}

	void VoiceConnection::processMessage(const std::string &message) {
		//json::Values values = json::getValues(message.c_str(),
		//	{ "op", "d" });
		rapidjson::Document values;
		values.Parse(message.c_str(), message.length());

		VoiceOPCode op = static_cast<VoiceOPCode>(json::toInt(values["op"]));
		json::Value& d = values["d"];
		switch (op) {
		case HELLO: {
			heartbeatInterval = d["heartbeat_interval"].GetDouble();

			//Don't sent a identity during resumes
			if (state & OPEN)
				break;

			std::string identity;
			/*The number 116 comes from the number of letters in this string + 1:
				{"op": 0,"d": {"server_id": "18446744073709551615",
				"user_id": "18446744073709551615","session_id": "","token": ""}}
			*/
			//remember to change the number below when editing identity
			identity.reserve(116 + context.sessionID.length() + context.token.length());
			identity +=
				"{"
					"\"op\": 0," //VoiceOPCode::IDENTIFY
					"\"d\": {"
						"\"server_id\": \"" ; identity += context.serverID ; identity += "\","
						"\"user_id\": \""   ; identity += origin->getID()  ; identity += "\","
						"\"session_id\": \""; identity += context.sessionID; identity += "\","
						"\"token\": \""     ; identity += context.token    ; identity += "\""
					"}"
				"}";
			origin->send(identity, connection);
			}
			state = static_cast<State>(state | CONNECTED);
			break;
		case READY: {
			//json::Values values = json::getValues(d->c_str(),
			//{ "ssrc", "port" });
			sSRC = d["ssrc"].GetUint();
			port = static_cast<uint16_t>(d["port"].GetUint());
			const json::Value& ipValue = d["ip"];
			std::string ip(ipValue.GetString(), ipValue.GetStringLength());
			//start heartbeating
			heartbeat();
			//connect to UDP
			UDP.setReceiveHandler([this](const std::vector<uint8_t>& iPDiscovery) {
				UDP.unsetReceiveHandler();
				// Taken from JDA
				// 4 leading bytes are nulls
				// last 2 bytes are the port in little edian
				size_t length = iPDiscovery.size();
				std::string receiveHost = std::string(reinterpret_cast<const char *>(&iPDiscovery[4]));
				uint16_t receivePort = (iPDiscovery[length - 2] & 0xff)
					| ((iPDiscovery[length - 1] & 0xff) << 8);
				//send Select Protocol Payload
				std::string protocol;
				/*The number 101 comes from the number of letters in this string + 1:
					{"op": 1,"d": {"protocol": "udp","data": {
					"address": "","port": 65535,
					"mode": "xsalsa20_poly1305"}}}
				*/
				protocol.reserve(101 + receiveHost.length());
				protocol +=
					"{"
						"\"op\": 1," //VoiceOPCode::SELECT_PROTOCOL
						"\"d\": {"
							"\"protocol\": \"udp\","
							"\"data\": {"
								"\"address\": \""; protocol += receiveHost                ; protocol += "\","
								"\"port\": "     ; protocol += std::to_string(receivePort); protocol +=   ","
								"\"mode\": \"xsalsa20_poly1305\""
							"}"
						"}"
					"}";
				origin->send(protocol, connection);
			});
			UDP.connect(ip, port);
			//IP Discovery
			unsigned char packet[70] = { 0 };
			packet[0] = (sSRC >> 24) & 0xff;
			packet[1] = (sSRC >> 16) & 0xff;
			packet[2] = (sSRC >>  8) & 0xff;
			packet[3] = (sSRC      ) & 0xff;
			UDP.send(packet, 70);
			}
			state = static_cast<State>(state | State::OPEN);
			break;
		case SESSION_DESCRIPTION: {
			const json::Value& secretKeyJSON = d["secret_key"];
			json::Array secretKeyJSONArray = secretKeyJSON.GetArray();
			const std::size_t secretKeyJSONArraySize = secretKeyJSONArray.Size();
			for (std::size_t i = 0; i < SECRET_KEY_SIZE && i < secretKeyJSONArraySize; ++i) {
					secretKey[i] = secretKeyJSONArray[i].GetUint() & 0xFF;
			}
			// Set speaking to true first, to bypass check
			wasPreviouslySpeaking = true;
			sendSpeaking(false);
			}
			state = static_cast<State>(state | State::AUDIO_ENABLED);
			if (context.eventHandler != nullptr)
				context.eventHandler->onReady(*this);
			break;
		case SPEAKING:
			if (context.eventHandler != nullptr)
				context.eventHandler->onSpeaking(*this);
		case RESUMED:
			break;
		case HEARTBEAT:
			send_heartbeat(false);
			break;
		case HEARTBEAT_ACK: {
			time_t previous_time = d.GetUint64();
			if (context.eventHandler != nullptr)
				context.eventHandler->onHeartbeatAck(*this,
					origin->getEpochTimeMillisecond() - previous_time);
			}
			break;
		default:
			break;
		}
	}

	void VoiceConnection::processCloseCode(const int16_t code) {
		//to do deal with close codes
		getDiscordClient().removeVoiceConnectionAndContext(*this);
	}

	void VoiceConnection::heartbeat() {
		send_heartbeat(true);
		heart = origin->schedule([this]() {
			this->heartbeat();
		}, heartbeatInterval);
	}

	void VoiceConnection::send_heartbeat(bool includeUDP) {
		std::string currentTime = std::to_string(origin->getEpochTimeMillisecond());
		std::string heartbeat;
		heartbeat.reserve(17 + currentTime.length());
		heartbeat +=
			"{"
				"\"op\": 3, "
				"\"d\": "; heartbeat += currentTime; heartbeat +=
			'}';
		origin->send(heartbeat, connection);

		if (includeUDP) {
			uint8_t udpPacket[] = {0xC9, 0, 0, 0, 0, 0, 0, 0, 0};
			UDP.send(udpPacket, 9);
		}

		if (context.eventHandler != nullptr)
			context.eventHandler->onHeartbeat(*this);
	}

	inline void VoiceConnection::scheduleNextTime(AudioTimer& timer, TimedTask code, const time_t interval) {
		timer.nextTime += interval;
		time_t delay = timer.nextTime - origin->getEpochTimeMillisecond();
		delay = 0 < delay ? delay : 0;

		timer.timer = origin->schedule(code, delay);
	}

	void VoiceConnection::startSpeaking() {
		if ((state & State::ABLE) != State::ABLE) return;

		if (!audioSource->isOpusEncoded())
#if defined(NONEXISTENT_OPUS)
			return;
#else
			if (!(state & CAN_ENCODE) || encoder == nullptr) {
				//init opus
				int opusError = 0;
				encoder = opus_encoder_create(
					/*Sampling rate(Hz)*/AudioTransmissionDetails::bitrate(),
					/*Channels*/         AudioTransmissionDetails::channels(),
					/*Mode*/             OPUS_APPLICATION_VOIP,
					&opusError);
				if (opusError) {//error check
					return;
				}
				state = static_cast<State>(state | State::CAN_ENCODE);
			}
#endif

		//say something
		speechTimer.nextTime = origin->getEpochTimeMillisecond();
		speak();
	}

	void VoiceConnection::sendSpeaking(bool isNowSpeaking) {
		if (isNowSpeaking) {
			state = static_cast<State>(state | State::SENDING_AUDIO);
		} else {
			state = static_cast<State>(state ^ State::SENDING_AUDIO);
		}

		if (lastTimeSentSpeakingState == 0) {
			lastTimeSentSpeakingState = origin->getEpochTimeMillisecond();
		} else {
			time_t currentTime = origin->getEpochTimeMillisecond();
			if (currentTime - lastTimeSentSpeakingState < 1000) {
				return; // Send speaking state in 1 sec interval to reduce traffic
			}
			lastTimeSentSpeakingState = currentTime;
		}

		if (wasPreviouslySpeaking == isNowSpeaking) {
			return;
		}
		wasPreviouslySpeaking = isNowSpeaking;

		std::string ssrc = std::to_string(sSRC);
		/*The number 44 comes from 1 plus the length of this string
			{"op":5,"d":{"speaking":0,"delay":0,"ssrc":}}
		*/
		std::string speaking;
		speaking.reserve(44 + ssrc.length());
		speaking +=
			"{"
				"\"op\":5,"
				"\"d\":{"
					"\"speaking\":"; speaking += isNowSpeaking ? "1" : "0"; speaking += ","
					"\"delay\":0,"
					"\"ssrc\":"; speaking += ssrc; speaking +=
				"}"
			"}";
		origin->send(speaking, connection);
	}

	void VoiceConnection::speak() {
		//check that we are can still send audio data
		if ((state & State::ABLE) != State::ABLE)
			return;

		AudioTransmissionDetails details(context, 0, samplesSentLastTime);

		std::size_t length = 0;

		//send the audio data
		if (silenceCounter < 10) {
			++silenceCounter;
			std::array<AudioSample, AudioTransmissionDetails::proposedLength()> silenceBytes{};
			AudioSample* ptr = silenceBytes.data();
			speak(ptr, silenceBytes.size(), false);
		} else {
			bool available = audioSource->frameAvailable();
			if (available) {
				sendSpeaking(true);
				if (audioSource->type == AUDIO_CONTAINER) {
					auto audioVectorSource = &static_cast<BasicAudioSourceForContainers&>(*audioSource);
					audioVectorSource->speak(*this, details, length);
				} else {
					AudioSample* audioBuffer = nullptr;
					bool opus = audioSource->isOpusEncoded();
					audioSource->read(details, audioBuffer, length);
					speak(audioBuffer, length, opus);
				}
			} else {
				sendSpeaking(false);
			}
		}

		//schedule next send
		const time_t interval = static_cast<time_t>(
			(static_cast<float>(length) / static_cast<float>(
				AudioTransmissionDetails::bitrate() * AudioTransmissionDetails::channels()
			)) * 1000.0f
		);

		scheduleNextTime(speechTimer,
			[this]() {
				this->speak();
			}, std::max(static_cast<size_t>(interval),
				AudioTransmissionDetails::proposedLengthOfTime())
		);
	}

	void VoiceConnection::speak(AudioSample*& audioData, const std::size_t & length, bool isOpus)  {
		samplesSentLastTime = 0;
		//This is only called in speak() so already checked that we can still send audio data

		//stop sending data when there's no data
		if (length == 0) {
			return;
		}

		//the >>1 cuts it in half since you are using 2 channels
		const std::size_t frameSize = length >> 1;

		if (!isOpus) {
#if defined(NONEXISTENT_OPUS)
			return;
#else
			//encode data
			constexpr opus_int32 encodedAudioMaxLength =
				static_cast<opus_int32>(AudioTransmissionDetails::proposedLength());
			unsigned char encodedAudioData[encodedAudioMaxLength]; //11.52 kilobytes
			opus_int32 encodedAudioLength = opus_encode(
				encoder, audioData, static_cast<int>(frameSize),
				encodedAudioData, encodedAudioMaxLength);
			//send it
			uint8_t * encodedAudioDataPointer = encodedAudioData;
			sendAudioData(encodedAudioDataPointer, encodedAudioLength, frameSize);
#endif
		} else {
			//encoded data should be in uint8
			sendAudioData(reinterpret_cast<uint8_t*&>(audioData), length, frameSize);
		}
	}

	void VoiceConnection::sendAudioData(
		uint8_t*& encodedAudioData,
		const std::size_t & length,
		const std::size_t & frameSize
	) {
#ifndef NONEXISTENT_SODIUM
		++sequence;

		const uint8_t header[rtpHeaderLength] = {
			0x80,
			0x78,
			static_cast<uint8_t>((sequence  >> (8 * 1)) & 0xff),
			static_cast<uint8_t>((sequence  >> (8 * 0)) & 0xff),
			static_cast<uint8_t>((timestamp >> (8 * 3)) & 0xff),
			static_cast<uint8_t>((timestamp >> (8 * 2)) & 0xff),
			static_cast<uint8_t>((timestamp >> (8 * 1)) & 0xff),
			static_cast<uint8_t>((timestamp >> (8 * 0)) & 0xff),
			static_cast<uint8_t>((sSRC      >> (8 * 3)) & 0xff),
			static_cast<uint8_t>((sSRC      >> (8 * 2)) & 0xff),
			static_cast<uint8_t>((sSRC      >> (8 * 1)) & 0xff),
			static_cast<uint8_t>((sSRC      >> (8 * 0)) & 0xff),
		};

		uint8_t nonce[nonceSize];
		std::memcpy(nonce                  , header, sizeof header);
		std::memset(nonce + rtpHeaderLength,      0, sizeof nonce - rtpHeaderLength);

		const size_t numOfBtyes = rtpHeaderLength + length + crypto_secretbox_MACBYTES;
		std::vector<uint8_t> audioDataPacket(numOfBtyes);
		std::memcpy(audioDataPacket.data(), header, rtpHeaderLength);

		crypto_secretbox_easy(audioDataPacket.data() + rtpHeaderLength,
			encodedAudioData, length, nonce, secretKey);

		UDP.send(audioDataPacket.data(), audioDataPacket.size());
		samplesSentLastTime = frameSize << 1;
		timestamp += static_cast<uint32_t>(frameSize);
#else
	#error Can not use voice without libsodium, libsodium not detected.
#endif
	}

	//To do test this
	void VoiceConnection::startListening() {
		if (!(state & CAN_DECODE) && !decoder) {
			decoder = std::make_unique<CustomOpusDecoder>();
		}
		listenTimer.nextTime = origin->getEpochTimeMillisecond();
		UDP.setReceiveHandler(std::bind(&VoiceConnection::processIncomingAudio,
			this, std::placeholders::_1));
	}

	int VoiceConnection::getPayloadOffset(const uint8_t* data, int csrcLength) const {
        // headerLength defines number of 4-byte words in the extension
        int16_t headerLength = (data[rtpHeaderLength + 2 + csrcLength] << 8)
			| (data[rtpHeaderLength + 2 + csrcLength + 1] & 0xff);
        size_t i = rtpHeaderLength // RTP header = 12 bytes
                + 4                    // header which defines a profile and length each 2-bytes = 4 bytes
                + csrcLength           // length of CSRC list (this seems to be always 0 when an extension exists)
                + headerLength * 4;    // number of 4-byte words in extension = len * 4 bytes

        // strip excess 0 bytes
        while (data[i] == 0) ++i;
        return i;
    }

	// Taken from JDA
	size_t VoiceConnection::getRTPOffset(const uint8_t* data) const {
		bool hasExtension = (data[0] & 0x10) != 0;
		uint8_t cc = data[0] & 0x0f;
		size_t csrcLength = cc * 4;
		uint16_t extension = hasExtension ?
			(data[rtpHeaderLength + csrcLength] << 8) | (data[rtpHeaderLength + csrcLength + 1] & 0xff) : 0;
		size_t offset = rtpHeaderLength + csrcLength;
		if (hasExtension && extension == discordRTPExtension) {
			offset = getPayloadOffset(data, csrcLength);
		}
		return offset;
	}

	void VoiceConnection::processIncomingAudio(const std::vector<uint8_t>& data)
	{
#if !defined(NONEXISTENT_SODIUM) || !defined(NONEXISTENT_OPUS)
		uint32_t ssrc = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
		size_t offset = getRTPOffset(data.data());

		//get nonce
		uint8_t nonce[nonceSize];
		std::memset(nonce + rtpHeaderLength, 0, nonceSize - rtpHeaderLength);
		std::memcpy(nonce, data.data(), rtpHeaderLength);

		//decrypt
		size_t decryptedDataSize = data.size() - offset - crypto_box_MACBYTES
			+ rtpHeaderLength; // RTP Header need to prepend it later
		uint8_t decryptedData[decryptedDataSize];

		bool isForged = crypto_secretbox_open_easy(
			decryptedData + rtpHeaderLength, data.data() + offset, data.size() - offset, nonce, secretKey
		) != 0;
		if (isForged)
			return;
		std::memcpy(decryptedData, data.data(), rtpHeaderLength); // Prepend RTP Header to decrypted data
		size_t decryptedOffset = getRTPOffset(decryptedData);

		uint8_t silenceBytes[] = {0xF8, 0xFF, 0xFE};
		if (std::memcmp(decryptedData + decryptedOffset, silenceBytes, 3) == 0)
			return;

		//decode
		AudioSample buf[AudioTransmissionDetails::proposedLength()] = { 0 };
		int read = decoder->decodeOpus(decryptedData + decryptedOffset, decryptedDataSize - decryptedOffset,
			buf);
		if (read <= 0)
			return;
		{
			std::lock_guard<std::mutex> lock(audioOutputLock);
			if (!audioOutput) {
				return;
			}
			AudioTransmissionDetails details(context, ssrc, 0);
			std::vector<AudioSample> decodedAudio(buf, buf + read * 2); // 2 channels
			audioOutput->write(decodedAudio, details);
		}
#endif
	}
}
#else
void SleepyDiscord::VoiceConnection::initialize() {}
void SleepyDiscord::VoiceConnection::processMessage(const std::string &/*message*/) {}
void SleepyDiscord::VoiceConnection::processCloseCode(const int16_t /*code*/) {}
#endif
