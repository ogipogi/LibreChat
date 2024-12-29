const express = require('express');

const {
  getSharedMessages,
  createSharedLink,
  updateSharedLink,
  getSharedLinks,
  deleteSharedLink,
} = require('~/models/Share');
const requireJwtAuth = require('~/server/middleware/requireJwtAuth');
const { isEnabled } = require('~/server/utils');
const router = express.Router();
const { logger } = require('~/config');

/**
 * Shared messages
 */
const allowSharedLinks =
  process.env.ALLOW_SHARED_LINKS === undefined || isEnabled(process.env.ALLOW_SHARED_LINKS);

if (allowSharedLinks) {
  const allowSharedLinksPublic =
    process.env.ALLOW_SHARED_LINKS_PUBLIC === undefined ||
    isEnabled(process.env.ALLOW_SHARED_LINKS_PUBLIC);
  router.get(
    '/:shareId',
    allowSharedLinksPublic ? (req, res, next) => next() : requireJwtAuth,
    async (req, res) => {
      try {
        const share = await getSharedMessages(req.params.shareId);

        if (share) {
          res.status(200).json(share);
        } else {
          res.status(404).end();
        }
      } catch (error) {
        res.status(500).json({ message: 'Error getting shared messages' });
      }
    },
  );

  /**
   * Shared links
   */
  router.get('/', requireJwtAuth, async (req, res) => {
    try {
      let pageNumber = req.query.pageNumber || 1;
      pageNumber = parseInt(pageNumber, 10);

      if (isNaN(pageNumber) || pageNumber < 1) {
        return res.status(400).json({ error: 'Invalid page number' });
      }

      let pageSize = req.query.pageSize || 25;
      pageSize = parseInt(pageSize, 10);

      if (isNaN(pageSize) || pageSize < 1) {
        return res.status(400).json({ error: 'Invalid page size' });
      }
      const isPublic = req.query.isPublic === 'true';
      res.status(200).send(await getSharedLinks(req.user.id, pageNumber, pageSize, isPublic));
    } catch (error) {
      res.status(500).json({ message: 'Error getting shared links' });
    }
  });

  router.post('/', requireJwtAuth, async (req, res) => {
    try {
      const encryptionKey = req.headers['x-encryption-key'];
      if (!encryptionKey) {
        return res.status(400).json({
          message: 'Encryption key required to share encrypted messages',
        });
      }

      const created = await createSharedLink(req.user.id, {
        ...req.body,
        encryptionKey,
      });
      if (created) {
        res.status(200).json(created);
      } else {
        res.status(404).end();
      }
    } catch (error) {
      logger.error('Error creating shared link:', error);
      res.status(500).json({ message: 'Error creating shared link' });
    }
  });

  router.patch('/', requireJwtAuth, async (req, res) => {
    try {
      const encryptionKey = req.headers['x-encryption-key'];
      const updated = await updateSharedLink(req.user.id, {
        ...req.body,
        encryptionKey,
      });
      if (updated) {
        res.status(200).json(updated);
      } else {
        res.status(404).end();
      }
    } catch (error) {
      res.status(500).json({ message: 'Error updating shared link' });
    }
  });

  router.delete('/:shareId', requireJwtAuth, async (req, res) => {
    try {
      const deleted = await deleteSharedLink(req.user.id, { shareId: req.params.shareId });
      if (deleted) {
        res.status(200).json(deleted);
      } else {
        res.status(404).end();
      }
    } catch (error) {
      res.status(500).json({ message: 'Error deleting shared link' });
    }
  });
}

module.exports = router;
