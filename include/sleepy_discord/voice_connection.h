#pragma once
#include <vector>
#include <array>
#include <cstdint>
#include <mutex>
#include <list>
#if (!defined(NONEXISTENT_OPUS) && !defined(SLEEPY_DISCORD_CMAKE)) || defined(EXISTENT_OPUS)
#include <opus.h>
#endif
#include "udp_client.h"
#include "snowflake.h"
#include "server.h"
#include "channel.h"
#include "message_receiver.h"
#include "timer.h"
#include "custom_opus_decoder.h"

namespace SleepyDiscord {
	using AudioSample = int16_t;

	class BaseDiscordClient;
	class VoiceConnection;

	class BaseVoiceEventHandler {
	public:

		virtual void onReady(VoiceConnection&) {}
		virtual void onSpeaking(VoiceConnection&) {}
		virtual void onEndSpeaking(VoiceConnection&) {}
		virtual void onFinishedSpeaking(VoiceConnection&) {}
		virtual void onHeartbeat(VoiceConnection&) {}
		virtual void onHeartbeatAck(VoiceConnection&, const time_t) {}
	};

	struct VoiceContext {
		friend VoiceConnection;
		friend BaseDiscordClient;
	public:
		inline Snowflake<Channel> getChannelID() const {
			return channelID;
		}

		inline Snowflake<Server> getServerID() const {
			return serverID;
		}

		inline bool operator==(const VoiceContext& right) {
			return this == &right;
		}

		inline void setVoiceHandler(BaseVoiceEventHandler* source) {
			eventHandler = std::unique_ptr<BaseVoiceEventHandler>(source);
		}

		inline const bool hasVoiceHandler() const {
			return eventHandler != nullptr;
		}

		inline BaseVoiceEventHandler& getVoiceHandler() {
			return *(eventHandler.get());
		}

		template<class EventHandler, class... Types>
		inline void startVoiceHandler(Types&&... arguments) {
			setVoiceHandler(new EventHandler(std::forward<Types>(arguments)...));
		}

		std::string sessionID = "";
		std::string endpoint = "";
		std::string token;

	private:
		VoiceContext(Snowflake<Server> _serverID, Snowflake<Channel> _channelID, BaseVoiceEventHandler* _eventHandler) :
			serverID(_serverID), channelID(_channelID), eventHandler(_eventHandler)
		{}

		Snowflake<Server> serverID;
		Snowflake<Channel> channelID;
		std::unique_ptr<BaseVoiceEventHandler> eventHandler;
	};

	enum AudioSourceType {
		AUDIO_BASE_TYPE,
		AUDIO_CONTAINER,
	};

	class VoiceConnection;

	struct AudioTransmissionDetails {
	public:
		inline VoiceContext& context() {
			return _context;
		}

		inline uint32_t ssrc() const {
			return _ssrc;
		}

		inline std::size_t amountSentSinceLastTime() {
			return _amountSentSinceLastTime;
		}

		static inline constexpr int bitrate() {
			return 48000;
		}

		static inline constexpr int channels() {
			return 2;
		}

		static inline constexpr std::size_t proposedLengthOfTime() {
			return 20;
		}

		static inline constexpr std::size_t proposedLength() {
			return static_cast<std::size_t>(
				bitrate() * channels() * (
					static_cast<float>(proposedLengthOfTime()) / 1000 /*millisecond conversion*/
				)
			);
		}

	private:
		friend VoiceConnection;
		AudioTransmissionDetails(
			VoiceContext& con,
			uint32_t ssrc,
			const std::size_t amo
		) :
			_context(con),
			_ssrc(ssrc),
			_amountSentSinceLastTime(amo)
		{ }

		VoiceContext& _context;
		uint32_t _ssrc;
		const std::size_t _amountSentSinceLastTime;
	};

	struct BaseAudioSource {
		BaseAudioSource() : type(AUDIO_BASE_TYPE) {}
		BaseAudioSource(AudioSourceType typ) : type(typ) {}
		virtual inline bool isOpusEncoded() { return false; }
		const AudioSourceType type;
		virtual ~BaseAudioSource() {}
		//This function below is here in case the user uses this class
		virtual void read(AudioTransmissionDetails& /*details*/, int16_t*& /*buffer*/, std::size_t& /*length*/) {};
		virtual bool frameAvailable() {
			return false;
		}
	};

	struct BaseAudioOutput {
		BaseAudioOutput() {}
		virtual ~BaseAudioOutput() {}
		virtual void write(std::vector<AudioSample>& audio, AudioTransmissionDetails& details) {}
		private:
		friend VoiceConnection;
	};

	struct AudioTimer {
		Timer timer;
		time_t nextTime = 0;
		void stop() {
			if (timer.isValid())
				timer.stop();
		}
	};

	class VoiceConnection : public GenericMessageReceiver {
	public:
		VoiceConnection(BaseDiscordClient* client, VoiceContext& _context);
		VoiceConnection(VoiceConnection&&) = default;

		~VoiceConnection() = default;

		inline bool operator==(const VoiceConnection& right) {
			return this == &right;
		}

		inline const bool isReady() {
			return state & State::ABLE;
		}

		inline void setAudioSource(BaseAudioSource*& source) {
			audioSource = std::unique_ptr<BaseAudioSource>(source);
		}

		inline const bool hasAudioSource() {
			return audioSource != nullptr;
		}

		inline BaseAudioSource& getAudioSource() {
			return *(audioSource.get());
		}

		/*To do there might be a way to prevent code reuse here*/

		inline void setAudioOutput(BaseAudioOutput*& output) {
			std::lock_guard<std::mutex> lock(audioOutputLock);
			audioOutput = std::unique_ptr<BaseAudioOutput>(output);
		}

		inline const bool hasAudioOutput() {
			std::lock_guard<std::mutex> lock(audioOutputLock);
			return audioOutput != nullptr;
		}

		inline BaseAudioOutput& getAudioOutput() {
			std::lock_guard<std::mutex> lock(audioOutputLock);
			return *(audioOutput.get());
		}

		//=== startSpeaking functions ===

		void startSpeaking();

		inline void startSpeaking(BaseAudioSource* source) {
			setAudioSource(source);
			startSpeaking();
		}

		template<class AudioSource, class... Types>
		inline void startSpeaking(Types&&... arguments) {
			startSpeaking(new AudioSource(std::forward<Types>(arguments)...));
		}

		//=== startListening ===

		void startListening();

		inline BaseDiscordClient& getDiscordClient() {
			return *origin;
		}

		inline BaseDiscordClient& getOrigin() {
			return getDiscordClient();
		}

		inline VoiceContext& getContext() {
			return context;
		}

		void speak(AudioSample*& audioData, const std::size_t& length, bool isOpus);

		void disconnect();

		inline const std::map<int64_t, uint32_t>& getUserSSRCs() const {
		  return userSSRCs;
		}

	private:
		friend BaseDiscordClient;

		void initialize() override;
		void processStream(JsonInputStream &is) override {}
		void processMessage(const std::string &message) override;
		void processCloseCode(const int16_t code) override;

		enum VoiceOPCode {
			IDENTIFY            = 0,  //client begin a voice websocket connection
			SELECT_PROTOCOL     = 1,  //client select the voice protocol
			READY               = 2,  //server complete the websocket handshake
			HEARTBEAT           = 3,  //client keep the websocket connection alive
			SESSION_DESCRIPTION = 4,  //server describe the session
			SPEAKING            = 5,  //both   indicate which users are speaking
			HEARTBEAT_ACK       = 6,  //server sent immediately following a received client heartbeat
			RESUME              = 7,  //client resume a connection
			HELLO               = 8,  //server the continuous interval in milliseconds after which the client should send a heartbeat
			RESUMED             = 9,  //server acknowledge Resume
			CLIENT_DISCONNECT   = 13  //server a client has disconnected from the voice channel
		};

		enum State : uint8_t {
			NOT_CONNECTED = 0 << 0,
			CONNECTED     = 1 << 0,
			OPEN          = 1 << 1,
			AUDIO_ENABLED = 1 << 2,
			SENDING_AUDIO = 1 << 3,

			CAN_ENCODE    = 1 << 6,
			CAN_DECODE    = 1 << 7,

			ABLE          = CONNECTED | OPEN | AUDIO_ENABLED,
		};

#ifdef NONEXISTENT_OPUS
		using OpusEncoder = void;
		using OpusDecoder = void;
#endif

		BaseDiscordClient* origin;
		VoiceContext& context;
		UDPClient UDP;
		time_t heartbeatInterval = 0;
		uint32_t sSRC;
		uint16_t port;
		Timer heart;
		State state = State::NOT_CONNECTED;
		int16_t numOfPacketsSent = 0;
		std::unique_ptr<BaseAudioSource> audioSource;
		std::unique_ptr<BaseAudioOutput> audioOutput;
		std::mutex audioOutputLock;
		AudioTimer speechTimer;
		AudioTimer listenTimer;
		std::size_t samplesSentLastTime = 0;
		time_t nextTime = 0;
		OpusEncoder *encoder = nullptr;
		std::map<int64_t, uint32_t> userSSRCs;
		std::mutex decodersLock;
		std::map<uint32_t, std::unique_ptr<CustomOpusDecoder>> decoders;
		uint16_t sequence = 0;
		uint32_t timestamp = 0;

		#define SECRET_KEY_SIZE 32
		unsigned char secretKey[SECRET_KEY_SIZE];
		static constexpr int nonceSize = 24;
		static constexpr int rtpHeaderLength = 12;
		static constexpr uint16_t discordRTPExtension = 0xBEDE;

		size_t silenceCounter = 0;
		bool wasPreviouslySpeaking = false;
		time_t lastTimeSentSpeakingState = 0;

		//to do use this for events
		template<class... Types>
		inline void callEvent(void (BaseVoiceEventHandler::*member)(Types...), Types&&... arguments){
			if(context.eventHandler != nullptr)
				((*context.eventHandler).*member)(arguments...);
		}
		void heartbeat();
		void send_heartbeat(bool includeUDP);
		inline void scheduleNextTime(AudioTimer& timer, TimedTask code, const time_t interval);
		inline void stopSpeaking() {
			state = static_cast<State>(state & ~SENDING_AUDIO);
		}
		void sendSpeaking(bool isNowSpeaking);
		void speak();
		void sendAudioData(
			uint8_t*& encodedAudioData,
			const std::size_t & length,
			const std::size_t & frameSize
		);
		void processIncomingAudio(const std::vector<uint8_t>& data);
		void ipDiscovery(const std::vector<uint8_t>& iPDiscovery);

		int getPayloadOffset(const uint8_t* data, int csrcLength) const;
		size_t getRTPOffset(const uint8_t* data) const;
	};

	struct BasicAudioSourceForContainers : public BaseAudioSource {
		BasicAudioSourceForContainers() : BaseAudioSource(AUDIO_CONTAINER) {}
		void read(AudioTransmissionDetails& /*details*/, int16_t*& /*buffer*/, std::size_t& /*length*/) override {}
		virtual void speak(
			VoiceConnection& connection,
			AudioTransmissionDetails& details,
			std::size_t& length
		) = 0;
	};

	template<class _Container>
	struct AudioSource : public BasicAudioSourceForContainers {
	public:
		using Container = _Container;
		AudioSource() : BasicAudioSourceForContainers() {}
		virtual void read(AudioTransmissionDetails& details, Container& target) {};
	private:
		friend VoiceConnection;
		void speak(
			VoiceConnection& connection,
			AudioTransmissionDetails& details,
			std::size_t& length
		) override {
			read(details, containedAudioData);
			int16_t* audioBuffer = containedAudioData.data();
			length = containedAudioData.size();
			connection.speak(audioBuffer, length, isOpusEncoded());
		}
	protected:
		Container containedAudioData;
	};

	struct AudioVectorSource : public AudioSource<std::vector<AudioSample>> {
	public:
		AudioVectorSource() : AudioSource<std::vector<AudioSample>>() {
			containedAudioData.resize(AudioTransmissionDetails::proposedLength());
		}
	};

	using AudioPointerSource = BaseAudioSource;
}
