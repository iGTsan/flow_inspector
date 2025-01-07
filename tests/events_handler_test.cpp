#include <gtest/gtest.h>
#include "events_handler.h"


namespace flow_inspector {


TEST(EventsHandlerTest, CreateEventHandlerWithLogger) {
  Logger logger;
  EventsHandler handler{logger};

  internal::Rule testRule{"TestRule"};
  internal::Packet testPacket{{1}};

  internal::Event testEvent{
    .type = internal::Event::EventType::Alert,
    .rule = testRule,
    .packet = testPacket,
  };

  handler.addEvent(testEvent);
  ::std::string output = logger.exportLogs();

  EXPECT_TRUE(output.find("Rule TestRule was matched.") != ::std::string::npos);
}

TEST(EventsHandlerTest, AddEventCallbackForAlertEventType) {
  Logger logger;
  EventsHandler eventsHandler(logger);

  bool callbackCalled = false;
  EventsHandler::EventCallback testCallback = [&callbackCalled](const internal::Event& event) {
    callbackCalled = true;
  };

  eventsHandler.addEventCallback(internal::Event::EventType::Alert, testCallback);

  internal::Event testEvent{
    .type = internal::Event::EventType::Alert,
    .rule = internal::Rule("TestRule"),
    .packet = internal::Packet({1}),
  };
  eventsHandler.addEvent(testEvent);

  EXPECT_TRUE(callbackCalled);
}

TEST(EventsHandlerTest, AddCustomEventCallbackForSpecificEventType) {
  Logger logger;
  EventsHandler eventsHandler{logger};

  bool customCallbackCalled = false;
  EventsHandler::EventCallback customCallback =
      [&customCallbackCalled](const internal::Event& event) {
        customCallbackCalled = true;
      };

  eventsHandler.addEventCallback(internal::Event::EventType::TestEvent, customCallback);

  internal::Event testEvent{
    .type = internal::Event::EventType::TestEvent,
    .rule = internal::Rule("TestRule"),
    .packet = internal::Packet({1, 2, 3, 4}),
  };
  eventsHandler.addEvent(testEvent);

  EXPECT_TRUE(customCallbackCalled);

  customCallbackCalled = false;
  internal::Event alertEvent{
    .type = internal::Event::EventType::Alert,
    .rule = internal::Rule("TestRule"),
    .packet = internal::Packet({1, 2, 3, 4}),
  };
  eventsHandler.addEvent(alertEvent);

  EXPECT_FALSE(customCallbackCalled);
}


TEST(EventsHandlerTest, HandleMultipleCallbacksForSameEventType) {
  Logger logger;
  EventsHandler eventsHandler{logger};

  int callbackCount = 0;
  EventsHandler::EventCallback testCallback1 = [&callbackCount](const internal::Event&) {
    callbackCount++;
  };
  EventsHandler::EventCallback testCallback2 = [&callbackCount](const internal::Event&) {
    callbackCount++;
  };

  eventsHandler.addEventCallback(internal::Event::EventType::Alert, testCallback1);
  eventsHandler.addEventCallback(internal::Event::EventType::Alert, testCallback2);

  internal::Event testEvent{
    .type = internal::Event::EventType::Alert,
    .rule = internal::Rule("TestRule"),
    .packet = internal::Packet({1, 2, 3, 4}),
  };
  eventsHandler.addEvent(testEvent);

  EXPECT_EQ(callbackCount, 2);
}

TEST(EventsHandlerTest, ShouldCorrectlyPassEventObjectToCallback) {
  Logger logger;
  EventsHandler eventsHandler{logger};
  internal::Packet testPacket{{1, 2, 3, 4}};

  EventsHandler::EventCallback testCallback = [&testPacket](const internal::Event& event) {
    EXPECT_EQ(event.type, internal::Event::EventType::TestEvent);
    EXPECT_EQ(event.packet, testPacket);
    EXPECT_EQ(event.packet.toString(), "[1 2 3 4]");
  };

  eventsHandler.addEventCallback(internal::Event::EventType::TestEvent, testCallback);

  internal::Event testEvent{
    .type = internal::Event::EventType::TestEvent,
    .rule = internal::Rule("TestRule"),
    .packet = testPacket,
  };
  eventsHandler.addEvent(testEvent);
}

}  // namespace flow_inspector
