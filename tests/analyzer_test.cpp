#include <gtest/gtest.h>

#include "analyzer.h"
#include "debug_logger.h"


namespace flow_inspector {


TEST(AnalyzerTest, LoadBadRule) {
  Logger logger;
  EventsHandler handler{logger};
  Analyzer analyzer{logger, handler};

  EXPECT_FALSE(loadFile(analyzer, "bad.rule"));
}


TEST(AnalyzerTest, LoadEmptyRule) {
  Logger logger;
  EventsHandler handler{logger};
  Analyzer analyzer{logger, handler};

  EXPECT_TRUE(loadFile(analyzer, "empty.rule"));
}


TEST(AnalyzerTest, LoadSingleSignature) {
  internal::getCoutLevel().enable();
  Logger logger;
  EventsHandler handler{logger};
  Analyzer analyzer{logger, handler};

  internal::Packet matched_packet{internal::rawPacketFromVector({0, 1, 2, 3, 4, 5, 6})};
  internal::Packet non_matched_packet{internal::rawPacketFromVector({0, 1, 2, 4, 5, 6})};

  // Alert; 1_sig; ([1 2 3 4])
  EXPECT_TRUE(loadFile(analyzer, "1_sig.rule"));
  size_t match_count = 0;

  EventsHandler::EventCallback callback = [&](const internal::Event& event) {
    EXPECT_TRUE(event.packet == matched_packet);
    match_count++;
  };

  handler.addEventCallback(internal::Event::EventType::Alert, callback);
  analyzer.detectThreats(non_matched_packet);
  analyzer.detectThreats(matched_packet);
  EXPECT_EQ(match_count, 1);
}


TEST(AnalyzerTest, LoadDoubleSignature) {
  Logger logger;
  EventsHandler handler{logger};
  Analyzer analyzer{logger, handler};

  internal::Packet matched_packet{internal::rawPacketFromVector({0, 1, 2, 3, 4, 1, 2, 3, 7})};
  internal::Packet non_matched_packet{internal::rawPacketFromVector({0, 1, 2, 4, 5, 6})};

  // Alert; 2_sig; ([1 2 3 4]); ([1 2 3 7])
  EXPECT_TRUE(loadFile(analyzer, "2_sig.rule"));
  size_t match_count = 0;

  EventsHandler::EventCallback callback = [&](const internal::Event& event) {
    EXPECT_EQ(event.packet, matched_packet);
    match_count++;
  };

  handler.addEventCallback(internal::Event::EventType::Alert, callback);
  analyzer.detectThreats(non_matched_packet);
  analyzer.detectThreats(matched_packet);
  EXPECT_EQ(match_count, 1);
}


TEST(AnalyzerTest, LoadSignatureWithOffset) {
  Logger logger;
  EventsHandler handler{logger};
  Analyzer analyzer{logger, handler};

  internal::Packet matched_packet{internal::rawPacketFromVector({0, 1, 2, 3, 4, 1, 2, 3, 7})};
  internal::Packet non_matched_packet{internal::rawPacketFromVector({1, 2, 3, 4, 5, 6})};

  // Alert; 1_sig; ([1 2 3 4], 1)
  EXPECT_TRUE(loadFile(analyzer, "1_sig_with_offset.rule"));
  size_t match_count = 0;

  EventsHandler::EventCallback callback = [&](const internal::Event& event) {
    EXPECT_EQ(event.packet, matched_packet);
    match_count++;
  };

  handler.addEventCallback(internal::Event::EventType::Alert, callback);
  analyzer.detectThreats(non_matched_packet);
  analyzer.detectThreats(matched_packet);
  EXPECT_EQ(match_count, 1);
}


TEST(AnalyzerTest, LoadTwoRules) {
  Logger logger;
  EventsHandler handler{logger};
  Analyzer analyzer{logger, handler};

  internal::Packet first_rule_packet{internal::rawPacketFromVector({0, 2, 3, 4, 5, 6})};
  internal::Packet second_rule_packet{internal::rawPacketFromVector({1, 2, 3, 4, 6})};
  internal::Packet both_rule_packet{internal::rawPacketFromVector({1, 2, 3, 4, 5, 6})};

  // TestEvent1; rule_1; ([3 4]); ([5 6])
  // TestEvent2; rule_2; ([1 2]); ([3 4])
  EXPECT_TRUE(loadFile(analyzer, "2_rules.rule"));
  size_t first_match_count = 0;
  size_t second_match_count = 0;

  EventsHandler::EventCallback first_callback = [&](const internal::Event& event) {
    EXPECT_NE(event.packet, second_rule_packet);
    first_match_count++;
  };

  EventsHandler::EventCallback second_callback = [&](const internal::Event& event) {
    EXPECT_NE(event.packet, first_rule_packet);
    second_match_count++;
  };

  handler.addEventCallback(internal::Event::EventType::TestEvent1, first_callback);
  handler.addEventCallback(internal::Event::EventType::TestEvent2, second_callback);
  analyzer.detectThreats(first_rule_packet);
  EXPECT_EQ(first_match_count, 1);
  EXPECT_EQ(second_match_count, 0);
  analyzer.detectThreats(second_rule_packet);
  EXPECT_EQ(first_match_count, 1);
  EXPECT_EQ(second_match_count, 1);
  analyzer.detectThreats(both_rule_packet);
  EXPECT_EQ(first_match_count, 2);
  EXPECT_EQ(second_match_count, 2);
}


TEST(AnalyzerTest, LoadTwoRulesWithSameSignature) {
  Logger logger;
  EventsHandler handler{logger};
  Analyzer analyzer{logger, handler};

  internal::Packet both_rule_packet{internal::rawPacketFromVector({0, 1, 2, 3, 4, 5, 6})};

  // TestEvent1; rule_1; ([1 2], 1)
  // TestEvent2; rule_2; ([1 2], 1)
  EXPECT_TRUE(loadFile(analyzer, "2_rules_same_sig.rule"));
  size_t first_match_count = 0;
  size_t second_match_count = 0;

  EventsHandler::EventCallback first_callback = [&](const internal::Event& event) {
    EXPECT_EQ(event.packet, both_rule_packet);
    first_match_count++;
  };

  EventsHandler::EventCallback second_callback = [&](const internal::Event& event) {
    EXPECT_EQ(event.packet, both_rule_packet);
    second_match_count++;
  };

  handler.addEventCallback(internal::Event::EventType::TestEvent1, first_callback);
  handler.addEventCallback(internal::Event::EventType::TestEvent2, second_callback);
  analyzer.detectThreats(both_rule_packet);
  EXPECT_EQ(first_match_count, 1);
  EXPECT_EQ(second_match_count, 1);
  EXPECT_EQ(analyzer.getSignaturesCount(), 1);
}


}  // namespace flow_inspector
