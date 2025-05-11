#include <gtest/gtest.h>

#include "events_handler.h"


namespace flow_inspector {


TEST(EventsHandlerTest, CreateEventHandlerWithLogger) {
  Logger logger;
  EventsHandler handler{logger};

  internal::Event test_event{
    .type = internal::Event::EventType::Alert,
    .rule = internal::Rule{"TestRule", internal::Event::EventType::Alert},
    .packet = internal::Packet{internal::rawPacketFromVector({1})},
  };

  handler.addEvent(test_event);
  ::std::string output = logger.exportLogs();

  EXPECT_TRUE(output.find("TestRule") != ::std::string::npos);
}

TEST(EventsHandlerTest, AddEventCallbackForAlertEventType) {
  Logger logger;
  EventsHandler events_handler(logger);

  bool callback_called = false;
  EventsHandler::EventCallback test_callback = [&callback_called](const internal::Event& event) {
    callback_called = true;
  };

  events_handler.addEventCallback(internal::Event::EventType::Alert, test_callback);

  internal::Event test_event{
    .type = internal::Event::EventType::Alert,
    .rule = internal::Rule{"TestRule", internal::Event::EventType::Alert},
    .packet = internal::Packet(internal::rawPacketFromVector({1})),
  };
  events_handler.addEvent(test_event);

  EXPECT_TRUE(callback_called);
}

TEST(EventsHandlerTest, AddCustomEventCallbackForSpecificEventType) {
  Logger logger;
  EventsHandler events_handler{logger};

  bool custom_callback_called = false;
  EventsHandler::EventCallback custom_callback =
      [&custom_callback_called](const internal::Event& event) {
        custom_callback_called = true;
      };

  events_handler.addEventCallback(internal::Event::EventType::TestEvent, custom_callback);

  internal::Event test_event{
    .type = internal::Event::EventType::TestEvent,
    .rule = internal::Rule{"TestRule", internal::Event::EventType::TestEvent},
    .packet = internal::Packet(internal::rawPacketFromVector({1, 2, 3, 4})),
  };
  events_handler.addEvent(test_event);

  EXPECT_TRUE(custom_callback_called);

  custom_callback_called = false;
  internal::Event alert_event{
    .type = internal::Event::EventType::Alert,
    .rule = internal::Rule{"TestRule", internal::Event::EventType::Alert},
    .packet = internal::Packet(internal::rawPacketFromVector({1, 2, 3, 4})),
  };
  events_handler.addEvent(alert_event);

  EXPECT_FALSE(custom_callback_called);
}


TEST(EventsHandlerTest, HandleMultipleCallbacksForSameEventType) {
  Logger logger;
  EventsHandler events_handler{logger};

  int callback_count = 0;
  EventsHandler::EventCallback test_callback1 = [&callback_count](const internal::Event&) {
    callback_count++;
  };
  EventsHandler::EventCallback test_callback2 = [&callback_count](const internal::Event&) {
    callback_count++;
  };

  events_handler.addEventCallback(internal::Event::EventType::Alert, test_callback1);
  events_handler.addEventCallback(internal::Event::EventType::Alert, test_callback2);

  internal::Event test_event{
    .type = internal::Event::EventType::Alert,
    .rule = internal::Rule{"TestRule", internal::Event::EventType::Alert},
    .packet = internal::Packet(internal::rawPacketFromVector({1, 2, 3, 4})),
  };
  events_handler.addEvent(test_event);

  EXPECT_EQ(callback_count, 2);
}

TEST(EventsHandlerTest, PassEventObjectToCallback) {
  Logger logger;
  EventsHandler events_handler{logger};
  internal::Packet test_packet{internal::rawPacketFromVector({1, 2, 3, 4})};

  EventsHandler::EventCallback test_callback = [&test_packet](const internal::Event& event) {
    EXPECT_EQ(event.type, internal::Event::EventType::TestEvent);
    EXPECT_EQ(event.packet, test_packet);
    EXPECT_EQ(event.packet.toString(), "[1 2 3 4]");
  };

  events_handler.addEventCallback(internal::Event::EventType::TestEvent, test_callback);

  internal::Event test_event{
    .type = internal::Event::EventType::TestEvent,
    .rule = internal::Rule{"TestRule", internal::Event::EventType::TestEvent},
    .packet = test_packet,
  };
  events_handler.addEvent(test_event);
}

}  // namespace flow_inspector
