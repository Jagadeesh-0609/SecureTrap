import { useEffect, useRef } from 'react';
import { useNavigationType } from 'react-router-dom';

/**
 * Move keyboard and screen-reader focus to a page's heading when the page was
 * reached by following a link inside the app.
 *
 * Following a link unmounts the link that had focus, so without this focus
 * falls back to the top of the document and nothing announces the new page.
 * A fresh load or the browser's back and forward buttons are left alone: the
 * browser already handles those, and stealing focus on first load would put
 * the header navigation behind the user's first Tab press.
 */
export function useHeadingFocus() {
  const headingRef = useRef<HTMLHeadingElement>(null);
  const navigationType = useNavigationType();

  useEffect(() => {
    if (navigationType === 'PUSH') {
      headingRef.current?.focus();
    }
  }, [navigationType]);

  return headingRef;
}
