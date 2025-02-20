import {BasketModel} from "../../../models/basket";

module.exports = function login () {
  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {
    BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const token = security.authorize(user)
        user.bid = basket.id // keep track of original basket
        security.authenticatedUsers.put(token, user)
        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
      }).catch((error: Error) => {
        next(error)
      })
  }

  const validateEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  return (req: Request, res: Response, next: NextFunction) => {
    const email = req.body.email || '';
    const password = req.body.password || '';

    // Input validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Use Sequelize model instead of raw query
    models.User.findOne({
      where: {
        email: email,
        password: security.hash(password),
        deletedAt: null
      },
      attributes: ['id', 'email', 'totpSecret'], // Only select needed fields
      raw: true
    })
      .then((user) => {
        if (!user) {
          return res.status(401).json({ error: 'Invalid email or password' });
        }

        if (user.totpSecret) {
          return res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: security.authorize({
                userId: user.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          });
        }

        // Wrap the user object to match the expected format
        const userWrapper = {
          data: user,
          bid: 0 // This will be set in afterLogin
        };

        afterLogin(userWrapper, res, next);
      })
      .catch((error: Error) => {
        // Log the error but don't expose details to client
        console.error('Authentication error:', error);
        res.status(500).json({ error: 'An error occurred during authentication' });
      })
  }
