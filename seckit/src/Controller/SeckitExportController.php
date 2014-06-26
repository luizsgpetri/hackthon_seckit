<?php
/**
 * @file
 * Contains \Drupal\seckit\Controller\SeckitExportController.
 */
namespace Drupal\seckit\Controller;
/**
 * Example page controller.
 */
class SeckitExportController {
  /**
   * Reports CSP violations to watchdog.
   */
  public function export() {
    // Only allow POST data with Content-Type application/csp-report
    // or application/json (the latter to support older user agents).
    // n.b. The CSP spec (1.0, 1.1) mandates this Content-Type header/value.
    // n.b. Content-Length is optional, so we don't check it.
    if (empty($_SERVER['CONTENT_TYPE']) || empty($_SERVER['REQUEST_METHOD'])) {
      return;
    }
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      return;
    }
    $pattern = '~^application/(csp-report|json)\h*(;|$)~';
    if (!preg_match($pattern, $_SERVER['CONTENT_TYPE'])) {
      return;
    }

    // Get and parse report.
    $reports = file_get_contents('php://input');
    $reports = json_decode($reports);
    if (!is_object($reports)) {
      return;
    }

    // Log the report data to watchdog.
    foreach ($reports as $report) {
      if (!isset($report->{'violated-directive'})) {
        continue;
      }
      $info = array(
        '@directive'   => $report->{'violated-directive'},
        '@blocked_uri' => $report->{'blocked-uri'},
        '@data'        => print_r($report, TRUE),
      );
      watchdog('seckit', 'CSP: Directive @directive violated.<br /> Blocked URI: @blocked_uri.<br /> <pre>Data: @data</pre>', $info, WATCHDOG_WARNING);
    }
  }
}
